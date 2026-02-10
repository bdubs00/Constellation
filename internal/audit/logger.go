package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Logger writes structured JSON audit events.
type Logger struct {
	mu     sync.Mutex
	writer io.Writer
}

// New creates a Logger that writes to the given writer.
func New(w io.Writer) *Logger {
	return &Logger{writer: w}
}

// ToolCallEvent represents a tool invocation audit record.
type ToolCallEvent struct {
	Server     string         `json:"server"`
	Tool       string         `json:"tool"`
	Arguments  map[string]any `json:"arguments"`
	Decision   string         `json:"decision"`
	Rule       int            `json:"matched_rule"`
	Reason     string         `json:"reason,omitempty"`
	DurationMs int64          `json:"duration_ms,omitempty"`
}

// LogToolCall records a tool invocation event.
func (l *Logger) LogToolCall(e ToolCallEvent) {
	record := map[string]any{
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"event":        "tool_call",
		"server":       e.Server,
		"tool":         e.Tool,
		"arguments":    e.Arguments,
		"decision":     e.Decision,
		"matched_rule": e.Rule,
	}
	if e.Reason != "" {
		record["reason"] = e.Reason
	}
	if e.DurationMs > 0 {
		record["duration_ms"] = e.DurationMs
	}
	l.write(record)
}

// LogStartup records a proxy startup event.
func (l *Logger) LogStartup(server, policyPath string) {
	l.write(map[string]any{
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"event":       "startup",
		"server":      server,
		"policy_file": policyPath,
	})
}

// LogShutdown records a proxy shutdown event.
func (l *Logger) LogShutdown(server string) {
	l.write(map[string]any{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"event":     "shutdown",
		"server":    server,
	})
}

func (l *Logger) write(record map[string]any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	data, err := json.Marshal(record)
	if err != nil {
		return
	}
	data = append(data, '\n')
	l.writer.Write(data)
}

// RedactSecrets replaces argument values that correspond to secret references
// with a redaction marker. Returns a new map; does not modify the original.
func RedactSecrets(args map[string]any, secretRefs map[string]string) map[string]any {
	redacted := make(map[string]any, len(args))
	for k, v := range args {
		redacted[k] = v
	}
	for envName, ref := range secretRefs {
		if _, exists := redacted[envName]; exists {
			redacted[envName] = "[REDACTED:" + ref + "]"
		}
	}
	return redacted
}
