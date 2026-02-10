package secrets

// Provider resolves secret references to their actual values.
type Provider interface {
	// Fetch resolves a secret reference string and returns the secret value.
	Fetch(reference string) (string, error)
}

// Resolve processes a map of env var names to secret references,
// resolving each through the appropriate provider.
// Returns a map of env var names to resolved values.
func Resolve(refs map[string]string, providers map[string]Provider) (map[string]string, error) {
	resolved := make(map[string]string, len(refs))
	for envName, ref := range refs {
		prefix, remainder := parseReference(ref)
		provider, ok := providers[prefix]
		if !ok {
			return nil, &UnknownProviderError{Prefix: prefix, Reference: ref}
		}
		val, err := provider.Fetch(remainder)
		if err != nil {
			return nil, &FetchError{Reference: ref, Err: err}
		}
		resolved[envName] = val
	}
	return resolved, nil
}

// parseReference splits "vault:secret/myapp#field" into ("vault", "secret/myapp#field").
func parseReference(ref string) (prefix string, remainder string) {
	for i, c := range ref {
		if c == ':' {
			return ref[:i], ref[i+1:]
		}
	}
	return "", ref
}

// UnknownProviderError is returned when a secret reference uses an unregistered prefix.
type UnknownProviderError struct {
	Prefix    string
	Reference string
}

func (e *UnknownProviderError) Error() string {
	return "unknown secrets provider \"" + e.Prefix + "\" in reference \"" + e.Reference + "\""
}

// FetchError wraps an error from a secrets provider.
type FetchError struct {
	Reference string
	Err       error
}

func (e *FetchError) Error() string {
	return "fetching secret \"" + e.Reference + "\": " + e.Err.Error()
}

func (e *FetchError) Unwrap() error {
	return e.Err
}
