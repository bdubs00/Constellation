package policy

import (
	"fmt"

	"github.com/bdubs00/constellation/internal/config"
)

// Engine evaluates tool calls against a server's policy rules.
type Engine struct {
	server config.Server
}

// NewEngine creates a policy engine for a server configuration.
func NewEngine(server config.Server) *Engine {
	return &Engine{server: server}
}

// Evaluate checks whether a tool call with the given arguments is allowed.
// Rules are evaluated top-down; first match wins.
func (e *Engine) Evaluate(tool string, arguments map[string]any) Decision {
	for i, rule := range e.server.Rules {
		if rule.Tool != tool {
			continue
		}
		if e.matchWhen(rule.When, arguments) {
			reason := fmt.Sprintf("matched rule %d", i)
			if !rule.Allow {
				reason = fmt.Sprintf("denied by rule %d", i)
			}
			return Decision{
				Allow:       rule.Allow,
				MatchedRule: i,
				Reason:      reason,
			}
		}
	}

	// No rule matched — fall back to default
	allow := e.server.Default == "allow"
	return Decision{
		Allow:       allow,
		MatchedRule: -1,
		Reason:      "no matching rule, using default: " + e.server.Default,
	}
}

// AllowedTools returns the list of tool names that have at least one allow rule.
// Used to filter tools/list responses.
func (e *Engine) AllowedTools() []string {
	seen := map[string]bool{}
	var tools []string
	for _, rule := range e.server.Rules {
		if rule.Allow && !seen[rule.Tool] {
			seen[rule.Tool] = true
			tools = append(tools, rule.Tool)
		}
	}
	return tools
}

// matchWhen checks if all 'when' clauses match the given arguments.
// All clauses must match (AND logic). Each clause is a glob pattern
// matched against the string representation of the argument value.
func (e *Engine) matchWhen(when map[string]string, arguments map[string]any) bool {
	for key, pattern := range when {
		val, ok := arguments[key]
		if !ok {
			return false
		}
		strVal := fmt.Sprintf("%v", val)
		if !GlobMatch(pattern, strVal) {
			return false
		}
	}
	return true
}
