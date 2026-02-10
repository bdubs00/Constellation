package proxy

import (
	"encoding/json"
	"fmt"
)

// Message represents a parsed JSON-RPC 2.0 message.
type Message struct {
	Raw    json.RawMessage
	ID     any             `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *RPCError       `json:"error,omitempty"`
}

// RPCError represents a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ToolCall represents a tools/call request's params.
type ToolCall struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// ToolInfo represents a single tool in a tools/list response.
type ToolInfo struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// ParseMessage parses a raw JSON-RPC message.
func ParseMessage(data []byte) (*Message, error) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("parsing JSON-RPC message: %w", err)
	}
	msg.Raw = data
	return &msg, nil
}

// AsToolCall extracts tool call parameters from a tools/call request.
func (m *Message) AsToolCall() (*ToolCall, error) {
	if m.Params == nil {
		return nil, fmt.Errorf("message has no params")
	}
	var tc ToolCall
	if err := json.Unmarshal(m.Params, &tc); err != nil {
		return nil, fmt.Errorf("parsing tool call params: %w", err)
	}
	return &tc, nil
}

// AsToolList extracts the tool list from a tools/list response.
func (m *Message) AsToolList() ([]ToolInfo, error) {
	if m.Result == nil {
		return nil, fmt.Errorf("message has no result")
	}
	var result struct {
		Tools []ToolInfo `json:"tools"`
	}
	if err := json.Unmarshal(m.Result, &result); err != nil {
		return nil, fmt.Errorf("parsing tool list: %w", err)
	}
	return result.Tools, nil
}

// FilterToolListResponse removes tools from a tools/list response that
// are not in the allowed list. Returns the modified JSON.
func FilterToolListResponse(raw json.RawMessage, allowed []string) ([]byte, error) {
	allowSet := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		allowSet[name] = true
	}

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}

	var result struct {
		Tools      []json.RawMessage `json:"tools"`
		NextCursor string            `json:"nextCursor,omitempty"`
	}
	if err := json.Unmarshal(envelope["result"], &result); err != nil {
		return nil, err
	}

	var filtered []json.RawMessage
	for _, toolRaw := range result.Tools {
		var info struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(toolRaw, &info); err != nil {
			continue
		}
		if allowSet[info.Name] {
			filtered = append(filtered, toolRaw)
		}
	}

	newResult := map[string]any{"tools": filtered}
	if result.NextCursor != "" {
		newResult["nextCursor"] = result.NextCursor
	}
	resultBytes, err := json.Marshal(newResult)
	if err != nil {
		return nil, err
	}

	envelope["result"] = resultBytes
	return json.Marshal(envelope)
}

// BuildErrorResponse creates a JSON-RPC error response.
func BuildErrorResponse(id any, code int, message string) []byte {
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	}
	data, _ := json.Marshal(resp)
	return data
}

// IsRequest returns true if this is a JSON-RPC request (has method and id).
func (m *Message) IsRequest() bool {
	return m.Method != "" && m.ID != nil
}

// IsResponse returns true if this is a JSON-RPC response (has result or error).
func (m *Message) IsResponse() bool {
	return m.Result != nil || m.Error != nil
}

// IsNotification returns true if this is a JSON-RPC notification (has method, no id).
func (m *Message) IsNotification() bool {
	return m.Method != "" && m.ID == nil
}
