package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadValidConfig(t *testing.T) {
	yaml := `
version: "1"
servers:
  filesystem:
    command: "npx"
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/home/user"]
    default: deny
    rules:
      - tool: read_file
        allow: true
        when:
          path: "/public/**"
      - tool: list_directory
        allow: true
`
	path := writeTempFile(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Version != "1" {
		t.Errorf("version = %q, want %q", cfg.Version, "1")
	}
	srv, ok := cfg.Servers["filesystem"]
	if !ok {
		t.Fatal("missing server 'filesystem'")
	}
	if srv.Command != "npx" {
		t.Errorf("command = %q, want %q", srv.Command, "npx")
	}
	if srv.Default != "deny" {
		t.Errorf("default = %q, want %q", srv.Default, "deny")
	}
	if len(srv.Rules) != 2 {
		t.Fatalf("rules count = %d, want 2", len(srv.Rules))
	}
	if srv.Rules[0].When["path"] != "/public/**" {
		t.Errorf("rule 0 when.path = %q, want %q", srv.Rules[0].When["path"], "/public/**")
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	path := writeTempFile(t, "{{invalid yaml")
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid",
			cfg: Config{
				Version: "1",
				Servers: map[string]Server{
					"test": {Command: "echo", Default: "deny"},
				},
			},
		},
		{
			name:    "missing version",
			cfg:     Config{Servers: map[string]Server{"test": {Command: "echo", Default: "deny"}}},
			wantErr: true,
		},
		{
			name:    "no servers",
			cfg:     Config{Version: "1"},
			wantErr: true,
		},
		{
			name: "missing command",
			cfg: Config{
				Version: "1",
				Servers: map[string]Server{"test": {Default: "deny"}},
			},
			wantErr: true,
		},
		{
			name: "invalid default",
			cfg: Config{
				Version: "1",
				Servers: map[string]Server{"test": {Command: "echo", Default: "maybe"}},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(&tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
