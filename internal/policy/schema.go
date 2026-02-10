package policy

// Decision is the result of a policy evaluation.
type Decision struct {
	Allow       bool
	MatchedRule int    // index of the matched rule, -1 if default was used
	Reason      string // human-readable explanation
}
