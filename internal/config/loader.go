package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Load reads and parses a constellation YAML policy file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if err := Validate(&cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

// Validate checks that a Config has all required fields and valid values.
func Validate(cfg *Config) error {
	if cfg.Version == "" {
		return fmt.Errorf("missing required field: version")
	}
	if len(cfg.Servers) == 0 {
		return fmt.Errorf("at least one server must be defined")
	}
	for name, srv := range cfg.Servers {
		if srv.Command == "" {
			return fmt.Errorf("server %q: missing required field: command", name)
		}
		if srv.Default != "deny" && srv.Default != "allow" {
			return fmt.Errorf("server %q: default must be \"deny\" or \"allow\", got %q", name, srv.Default)
		}
		for i, rule := range srv.Rules {
			if rule.Tool == "" {
				return fmt.Errorf("server %q: rule %d: missing required field: tool", name, i)
			}
		}
	}
	return nil
}
