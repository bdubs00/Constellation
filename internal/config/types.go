package config

// Config is the top-level constellation.yaml structure.
type Config struct {
	Version string            `yaml:"version"`
	Vault   *VaultConfig      `yaml:"vault,omitempty"`
	Servers map[string]Server `yaml:"servers"`
}

// VaultConfig holds Vault connection and auth settings.
type VaultConfig struct {
	Address string     `yaml:"address"`
	TLS     TLSConfig  `yaml:"tls,omitempty"`
	Auth    AuthConfig `yaml:"auth"`
}

type TLSConfig struct {
	CACert     string `yaml:"ca_cert,omitempty"`
	SkipVerify bool   `yaml:"skip_verify,omitempty"`
}

type AuthConfig struct {
	Method       string `yaml:"method"`
	RoleIDPath   string `yaml:"role_id_path,omitempty"`
	SecretIDPath string `yaml:"secret_id_path,omitempty"`
}

// Server defines an MCP server and its access policy.
type Server struct {
	Command string         `yaml:"command"`
	Args    []string       `yaml:"args,omitempty"`
	Secrets *SecretsConfig `yaml:"secrets,omitempty"`
	Default string         `yaml:"default"`
	Rules   []Rule         `yaml:"rules,omitempty"`
}

type SecretsConfig struct {
	Env map[string]string `yaml:"env,omitempty"`
}

// Rule defines a single policy rule for a tool.
type Rule struct {
	Tool  string            `yaml:"tool"`
	Allow bool              `yaml:"allow"`
	When  map[string]string `yaml:"when,omitempty"`
}
