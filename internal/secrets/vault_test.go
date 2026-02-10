package secrets

import (
	"testing"
)

func TestVaultReferenceParsingViaFetch(t *testing.T) {
	// We can't test against a real Vault in unit tests.
	// This test verifies the reference format validation.
	// Integration tests with a real Vault belong in a separate test suite.

	// Test that a reference without # is rejected
	p := &VaultProvider{client: nil}
	_, err := p.Fetch("secret/myapp")
	if err == nil {
		t.Fatal("expected error for reference without #")
	}
}
