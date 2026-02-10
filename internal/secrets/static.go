package secrets

import (
	"fmt"
	"os"
)

// StaticProvider resolves "env:" references by reading environment variables.
type StaticProvider struct{}

// NewStaticProvider creates a provider that reads from environment variables.
func NewStaticProvider() *StaticProvider {
	return &StaticProvider{}
}

// Fetch reads the named environment variable.
func (p *StaticProvider) Fetch(name string) (string, error) {
	val, ok := os.LookupEnv(name)
	if !ok {
		return "", fmt.Errorf("environment variable %q not set", name)
	}
	return val, nil
}
