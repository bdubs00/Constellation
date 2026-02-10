package proxy

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/bdubs00/constellation/internal/audit"
	"github.com/bdubs00/constellation/internal/config"
	"github.com/bdubs00/constellation/internal/policy"
)

// mockProcess simulates an MCP server's stdin/stdout for testing.
type mockProcess struct {
	stdin  *bytes.Buffer // what the proxy writes to the server
	stdout io.Reader     // what the server sends back to the proxy
}

func TestProxyAllowedToolCall(t *testing.T) {
	srv := config.Server{
		Default: "deny",
		Rules:   []config.Rule{{Tool: "read_file", Allow: true}},
	}
	engine := policy.NewEngine(srv)
	auditBuf := &bytes.Buffer{}
	logger := audit.New(auditBuf)

	// Client sends a tools/call request
	clientInput := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/test"}}}` + "\n"

	// Server would respond
	serverResponse := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"file contents"}]}}` + "\n"

	clientReader := strings.NewReader(clientInput)
	clientWriter := &bytes.Buffer{}
	serverStdin := &bytes.Buffer{}
	serverStdout := strings.NewReader(serverResponse)

	p := &Proxy{
		engine:       engine,
		logger:       logger,
		serverName:   "test",
		dryRun:       false,
		serverStdin:  serverStdin,
		serverStdout: serverStdout,
		clientReader: clientReader,
		clientWriter: clientWriter,
	}

	p.handleClientMessage([]byte(strings.TrimSpace(clientInput)))

	// The message should have been forwarded to the server
	if serverStdin.Len() == 0 {
		t.Error("expected message to be forwarded to server")
	}

	// Audit log should show allow
	if !strings.Contains(auditBuf.String(), `"allow"`) {
		t.Errorf("audit log missing allow decision: %s", auditBuf.String())
	}
}

func TestProxyDeniedToolCall(t *testing.T) {
	srv := config.Server{
		Default: "deny",
		Rules:   []config.Rule{},
	}
	engine := policy.NewEngine(srv)
	auditBuf := &bytes.Buffer{}
	logger := audit.New(auditBuf)

	clientInput := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/etc/passwd"}}}`

	clientWriter := &bytes.Buffer{}
	serverStdin := &bytes.Buffer{}

	p := &Proxy{
		engine:       engine,
		logger:       logger,
		serverName:   "test",
		dryRun:       false,
		serverStdin:  serverStdin,
		serverStdout: strings.NewReader(""),
		clientReader: strings.NewReader(""),
		clientWriter: clientWriter,
	}

	p.handleClientMessage([]byte(clientInput))

	// Should NOT be forwarded to the server
	if serverStdin.Len() != 0 {
		t.Error("denied message should not be forwarded to server")
	}

	// Should send error response back to client
	if !strings.Contains(clientWriter.String(), "denied by policy") {
		t.Errorf("expected denial response, got: %s", clientWriter.String())
	}

	// Audit log should show deny
	if !strings.Contains(auditBuf.String(), `"deny"`) {
		t.Errorf("audit log missing deny decision: %s", auditBuf.String())
	}
}

func TestProxyPassthroughMessage(t *testing.T) {
	srv := config.Server{Default: "deny"}
	engine := policy.NewEngine(srv)
	logger := audit.New(&bytes.Buffer{})

	// Non-tool-call messages should pass through
	msg := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`

	serverStdin := &bytes.Buffer{}

	p := &Proxy{
		engine:       engine,
		logger:       logger,
		serverName:   "test",
		serverStdin:  serverStdin,
		serverStdout: strings.NewReader(""),
		clientReader: strings.NewReader(""),
		clientWriter: &bytes.Buffer{},
	}

	p.handleClientMessage([]byte(msg))

	if serverStdin.Len() == 0 {
		t.Error("non-tool-call message should pass through to server")
	}
}

func TestProxyDryRun(t *testing.T) {
	srv := config.Server{
		Default: "deny",
		Rules:   []config.Rule{},
	}
	engine := policy.NewEngine(srv)
	auditBuf := &bytes.Buffer{}
	logger := audit.New(auditBuf)

	msg := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/etc/passwd"}}}`

	serverStdin := &bytes.Buffer{}

	p := &Proxy{
		engine:       engine,
		logger:       logger,
		serverName:   "test",
		dryRun:       true,
		serverStdin:  serverStdin,
		serverStdout: strings.NewReader(""),
		clientReader: strings.NewReader(""),
		clientWriter: &bytes.Buffer{},
	}

	p.handleClientMessage([]byte(msg))

	// In dry-run, even denied calls get forwarded
	if serverStdin.Len() == 0 {
		t.Error("dry-run mode should forward all calls")
	}

	// But audit log should still show deny
	if !strings.Contains(auditBuf.String(), `"deny"`) {
		t.Errorf("audit log missing deny decision in dry-run: %s", auditBuf.String())
	}
}
