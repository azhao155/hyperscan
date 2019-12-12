package waf

import (
	"io"
)

// HeaderPair represents a header line in an HTTP request.
type HeaderPair interface {
	Key() string
	Value() string
}

// RequestLogMetaData is the data needed by logging.
type RequestLogMetaData interface {
	Scope() string
	ScopeName() string
}

// HTTPRequest represents an HTTP request to be evaluated by the WAF.
type HTTPRequest interface {
	ConfigID() string
	Method() string
	URI() string
	Protocol() string
	RemoteAddr() string
	Headers() []HeaderPair
	BodyReader() io.Reader
	LogMetaData() RequestLogMetaData
	TransactionID() string
}
