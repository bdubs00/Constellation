package secrets

import (
	"os"
	"testing"
)

func TestStaticProviderFromEnv(t *testing.T) {
	os.Setenv("TEST_SECRET_VALUE", "hunter2")
	defer os.Unsetenv("TEST_SECRET_VALUE")

	p := NewStaticProvider()
	val, err := p.Fetch("TEST_SECRET_VALUE")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "hunter2" {
		t.Errorf("got %q, want %q", val, "hunter2")
	}
}

func TestStaticProviderMissing(t *testing.T) {
	os.Unsetenv("NONEXISTENT_VAR")
	p := NewStaticProvider()
	_, err := p.Fetch("NONEXISTENT_VAR")
	if err == nil {
		t.Fatal("expected error for missing env var")
	}
}

func TestResolveWithProviders(t *testing.T) {
	os.Setenv("MY_TOKEN", "abc123")
	defer os.Unsetenv("MY_TOKEN")

	providers := map[string]Provider{
		"env": NewStaticProvider(),
	}

	refs := map[string]string{
		"API_TOKEN": "env:MY_TOKEN",
	}

	resolved, err := Resolve(refs, providers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved["API_TOKEN"] != "abc123" {
		t.Errorf("API_TOKEN = %q, want %q", resolved["API_TOKEN"], "abc123")
	}
}

func TestResolveUnknownProvider(t *testing.T) {
	providers := map[string]Provider{}
	refs := map[string]string{
		"SECRET": "unknown:something",
	}
	_, err := Resolve(refs, providers)
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}
