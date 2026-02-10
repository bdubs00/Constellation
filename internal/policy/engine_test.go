package policy

import (
	"testing"

	"github.com/bdubs00/constellation/internal/config"
)

func TestEvaluateDefaultDeny(t *testing.T) {
	srv := config.Server{
		Default: "deny",
		Rules:   []config.Rule{},
	}
	engine := NewEngine(srv)
	d := engine.Evaluate("read_file", map[string]any{"path": "/etc/passwd"})
	if d.Allow {
		t.Error("expected deny for unmatched tool")
	}
	if d.MatchedRule != -1 {
		t.Errorf("matched_rule = %d, want -1", d.MatchedRule)
	}
}

func TestEvaluateToolAllowed(t *testing.T) {
	srv := config.Server{
		Default: "deny",
		Rules: []config.Rule{
			{Tool: "list_directory", Allow: true},
		},
	}
	engine := NewEngine(srv)
	d := engine.Evaluate("list_directory", map[string]any{})
	if !d.Allow {
		t.Error("expected allow for matching tool")
	}
	if d.MatchedRule != 0 {
		t.Errorf("matched_rule = %d, want 0", d.MatchedRule)
	}
}

func TestEvaluateWhenClauseMatches(t *testing.T) {
	srv := config.Server{
		Default: "deny",
		Rules: []config.Rule{
			{Tool: "read_file", Allow: true, When: map[string]string{"path": "/public/**"}},
		},
	}
	engine := NewEngine(srv)

	d := engine.Evaluate("read_file", map[string]any{"path": "/public/readme.md"})
	if !d.Allow {
		t.Error("expected allow for matching path")
	}

	d = engine.Evaluate("read_file", map[string]any{"path": "/private/secret.txt"})
	if d.Allow {
		t.Error("expected deny for non-matching path")
	}
}

func TestEvaluateFirstMatchWins(t *testing.T) {
	srv := config.Server{
		Default: "deny",
		Rules: []config.Rule{
			{Tool: "write_file", Allow: false, When: map[string]string{"path": "/protected/**"}},
			{Tool: "write_file", Allow: true},
		},
	}
	engine := NewEngine(srv)

	d := engine.Evaluate("write_file", map[string]any{"path": "/protected/data.txt"})
	if d.Allow {
		t.Error("expected deny from first matching rule")
	}
	if d.MatchedRule != 0 {
		t.Errorf("matched_rule = %d, want 0", d.MatchedRule)
	}

	d = engine.Evaluate("write_file", map[string]any{"path": "/tmp/scratch.txt"})
	if !d.Allow {
		t.Error("expected allow from second rule")
	}
	if d.MatchedRule != 1 {
		t.Errorf("matched_rule = %d, want 1", d.MatchedRule)
	}
}

func TestEvaluateDefaultAllow(t *testing.T) {
	srv := config.Server{
		Default: "allow",
		Rules:   []config.Rule{},
	}
	engine := NewEngine(srv)
	d := engine.Evaluate("anything", map[string]any{})
	if !d.Allow {
		t.Error("expected allow for default-allow server")
	}
}

func TestEvaluateMultipleWhenClauses(t *testing.T) {
	srv := config.Server{
		Default: "deny",
		Rules: []config.Rule{
			{
				Tool:  "query",
				Allow: true,
				When:  map[string]string{"database": "public_*", "table": "users"},
			},
		},
	}
	engine := NewEngine(srv)

	// Both match
	d := engine.Evaluate("query", map[string]any{"database": "public_main", "table": "users"})
	if !d.Allow {
		t.Error("expected allow when all when clauses match")
	}

	// One doesn't match
	d = engine.Evaluate("query", map[string]any{"database": "private_db", "table": "users"})
	if d.Allow {
		t.Error("expected deny when one when clause fails")
	}
}
