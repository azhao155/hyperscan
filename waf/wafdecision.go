package waf

// Decision denotes WAF's response to a request
type Decision int

const (
	_ Decision = iota
	// Pass means that the request should be allowed
	Pass

	// Allow means that the request should be allowed regardless of remaining rules
	Allow

	// Block means that the request should be blocked regardless of remaining rules
	Block
)
