//go:build ignore

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

// Minimal MCP server that responds to initialize and tools/list,
// and echoes back tools/call arguments.
func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		var msg map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			continue
		}

		id := msg["id"]
		method, _ := msg["method"].(string)

		var resp map[string]any

		switch method {
		case "initialize":
			resp = map[string]any{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]any{
					"protocolVersion": "2024-11-05",
					"capabilities":    map[string]any{"tools": map[string]any{}},
					"serverInfo":      map[string]any{"name": "echo-server", "version": "0.1.0"},
				},
			}
		case "tools/list":
			resp = map[string]any{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]any{
					"tools": []any{
						map[string]any{"name": "read_file", "description": "Read a file", "inputSchema": map[string]any{"type": "object"}},
						map[string]any{"name": "write_file", "description": "Write a file", "inputSchema": map[string]any{"type": "object"}},
						map[string]any{"name": "list_directory", "description": "List directory", "inputSchema": map[string]any{"type": "object"}},
					},
				},
			}
		case "tools/call":
			params, _ := msg["params"].(map[string]any)
			resp = map[string]any{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]any{
					"content": []any{
						map[string]any{"type": "text", "text": fmt.Sprintf("called %v", params["name"])},
					},
				},
			}
		default:
			resp = map[string]any{
				"jsonrpc": "2.0",
				"id":      id,
				"result":  map[string]any{},
			}
		}

		data, _ := json.Marshal(resp)
		fmt.Fprintln(os.Stdout, string(data))
	}
}
