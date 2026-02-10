package proxy

import (
	"testing"
)

func TestParseToolCallRequest(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/public/readme.md"}}}`

	msg, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg.Method != "tools/call" {
		t.Errorf("method = %q, want %q", msg.Method, "tools/call")
	}
	if msg.ID == nil {
		t.Fatal("expected non-nil ID")
	}

	tc, err := msg.AsToolCall()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc.Name != "read_file" {
		t.Errorf("tool name = %q, want %q", tc.Name, "read_file")
	}
	if tc.Arguments["path"] != "/public/readme.md" {
		t.Errorf("path = %q, want %q", tc.Arguments["path"], "/public/readme.md")
	}
}

func TestParseToolListResponse(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file","description":"Read a file","inputSchema":{}},{"name":"write_file","description":"Write a file","inputSchema":{}}]}}`

	msg, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tools, err := msg.AsToolList()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tools) != 2 {
		t.Fatalf("tool count = %d, want 2", len(tools))
	}
	if tools[0].Name != "read_file" {
		t.Errorf("tool 0 name = %q, want %q", tools[0].Name, "read_file")
	}
}

func TestFilterToolList(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file","description":"Read","inputSchema":{}},{"name":"write_file","description":"Write","inputSchema":{}},{"name":"list_directory","description":"List","inputSchema":{}}]}}`

	msg, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}

	allowed := []string{"read_file", "list_directory"}
	filtered, err := FilterToolListResponse(msg.Raw, allowed)
	if err != nil {
		t.Fatal(err)
	}

	// Parse the filtered response to verify
	fmsg, err := ParseMessage(filtered)
	if err != nil {
		t.Fatal(err)
	}
	tools, err := fmsg.AsToolList()
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 2 {
		t.Fatalf("filtered tool count = %d, want 2", len(tools))
	}
	for _, tool := range tools {
		if tool.Name == "write_file" {
			t.Error("write_file should have been filtered out")
		}
	}
}

func TestParseNonToolMessage(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	msg, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Method != "initialize" {
		t.Errorf("method = %q, want %q", msg.Method, "initialize")
	}
}

func TestBuildErrorResponse(t *testing.T) {
	resp := BuildErrorResponse(1, -32600, "tool call denied by policy")
	msg, err := ParseMessage(resp)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Error == nil {
		t.Fatal("expected error field")
	}
	if msg.Error.Code != -32600 {
		t.Errorf("error code = %d, want -32600", msg.Error.Code)
	}
}
