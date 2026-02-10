package policy

import "github.com/bmatcuk/doublestar/v4"

// GlobMatch checks if a value matches a glob pattern.
// Supports ** for recursive matching.
func GlobMatch(pattern, value string) bool {
	matched, err := doublestar.Match(pattern, value)
	if err != nil {
		return false
	}
	return matched
}
