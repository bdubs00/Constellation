package audit

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestLogToolCall(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf)

	logger.LogToolCall(ToolCallEvent{
		Server:    "filesystem",
		Tool:      "read_file",
		Arguments: map[string]any{"path": "/public/readme.md"},
		Decision:  "allow",
		Rule:      0,
	})

	var event map[string]any
	if err := json.NewDecoder(&buf).Decode(&event); err != nil {
		t.Fatalf("failed to decode log output: %v", err)
	}

	if event["event"] != "tool_call" {
		t.Errorf("event = %q, want %q", event["event"], "tool_call")
	}
	if event["server"] != "filesystem" {
		t.Errorf("server = %q, want %q", event["server"], "filesystem")
	}
	if event["tool"] != "read_file" {
		t.Errorf("tool = %q, want %q", event["tool"], "read_file")
	}
	if event["decision"] != "allow" {
		t.Errorf("decision = %q, want %q", event["decision"], "allow")
	}
	if _, ok := event["timestamp"]; !ok {
		t.Error("missing timestamp field")
	}
}

func TestLogDenied(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf)

	logger.LogToolCall(ToolCallEvent{
		Server:    "filesystem",
		Tool:      "write_file",
		Arguments: map[string]any{"path": "/etc/passwd"},
		Decision:  "deny",
		Rule:      -1,
		Reason:    "no matching allow rule",
	})

	var event map[string]any
	if err := json.NewDecoder(&buf).Decode(&event); err != nil {
		t.Fatalf("failed to decode log output: %v", err)
	}
	if event["decision"] != "deny" {
		t.Errorf("decision = %q, want %q", event["decision"], "deny")
	}
	if event["reason"] != "no matching allow rule" {
		t.Errorf("reason = %q, want %q", event["reason"], "no matching allow rule")
	}
}

func TestLogStartup(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf)

	logger.LogStartup("filesystem", "/path/to/policy.yaml")

	var event map[string]any
	if err := json.NewDecoder(&buf).Decode(&event); err != nil {
		t.Fatalf("failed to decode log output: %v", err)
	}
	if event["event"] != "startup" {
		t.Errorf("event = %q, want %q", event["event"], "startup")
	}
	if event["server"] != "filesystem" {
		t.Errorf("server = %q, want %q", event["server"], "filesystem")
	}
}

func TestRedactSecrets(t *testing.T) {
	refs := map[string]string{
		"API_KEY": "vault:secret/myapp#api_key",
	}
	args := map[string]any{
		"key":  "supersecretvalue",
		"name": "visible",
	}
	redacted := RedactSecrets(args, refs)
	if redacted["name"] != "visible" {
		t.Errorf("non-secret value was modified")
	}
}
