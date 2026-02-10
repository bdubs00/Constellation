package policy

import "testing"

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"/public/**", "/public/readme.md", true},
		{"/public/**", "/public/sub/deep/file.txt", true},
		{"/public/**", "/private/secret.txt", false},
		{"/tmp/*.log", "/tmp/app.log", true},
		{"/tmp/*.log", "/tmp/sub/app.log", false},
		{"*.json", "config.json", true},
		{"*.json", "config.yaml", false},
		{"exact-match", "exact-match", true},
		{"exact-match", "not-a-match", false},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.value, func(t *testing.T) {
			got := GlobMatch(tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("GlobMatch(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}
