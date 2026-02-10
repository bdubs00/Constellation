package integration

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProxyEndToEnd(t *testing.T) {
	// Build the echo server
	echoServer := filepath.Join(t.TempDir(), "echo-server")
	build := exec.Command("go", "build", "-o", echoServer, "./echo_server.go")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building echo server: %v\n%s", err, out)
	}

	// Build constellation
	constellation := filepath.Join(t.TempDir(), "constellation")
	build = exec.Command("go", "build", "-o", constellation, "../../cmd/constellation")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building constellation: %v\n%s", err, out)
	}

	// Write a test policy
	policyContent := `
version: "1"
servers:
  echo:
    command: "` + echoServer + `"
    default: deny
    rules:
      - tool: read_file
        allow: true
        when:
          path: "/public/**"
      - tool: list_directory
        allow: true
`
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	os.WriteFile(policyPath, []byte(policyContent), 0644)

	// Start constellation
	cmd := exec.Command(constellation, "run", "--server", "echo", "--policy", policyPath)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting constellation: %v", err)
	}
	defer cmd.Process.Kill()

	scanner := bufio.NewScanner(stdout)
	send := func(msg string) string {
		stdin.Write([]byte(msg + "\n"))
		if scanner.Scan() {
			return scanner.Text()
		}
		return ""
	}

	// Give it a moment to start
	time.Sleep(200 * time.Millisecond)

	// Test 1: Allowed tool call should pass through
	resp := send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/public/test.txt"}}}`)
	if !strings.Contains(resp, "called read_file") {
		t.Errorf("allowed call should pass through, got: %s", resp)
	}

	// Test 2: Denied tool call should return error
	resp = send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/etc/passwd"}}}`)
	if !strings.Contains(resp, "denied by policy") {
		t.Errorf("denied call should return error, got: %s", resp)
	}

	// Test 3: Non-tool messages pass through
	resp = send(`{"jsonrpc":"2.0","id":3,"method":"initialize","params":{}}`)
	var initResp map[string]any
	json.Unmarshal([]byte(resp), &initResp)
	if initResp["error"] != nil {
		t.Errorf("initialize should pass through, got error: %s", resp)
	}

	stdin.Close()
}
