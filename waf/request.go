package waf

import "io"

// HeaderPair represents a header line in an HTTP request.
type HeaderPair interface {
	Key() string
	Value() string
}

// HTTPRequest represents an HTTP request to be evaluated by the WAF.
type HTTPRequest interface {
	SecRuleID() string
	Version() int64
	Method() string
	URI() string
	Headers() []HeaderPair
	BodyReader() io.Reader
}
