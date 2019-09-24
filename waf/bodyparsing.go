package waf

import (
	"errors"
	"github.com/rs/zerolog"
	"io"
)

// ParsedBodyFieldCb is will be called for each parsed field.
type ParsedBodyFieldCb = func(contentType ContentType, fieldName string, data string) error

// RequestBodyParser parses HTTP request bodies.
type RequestBodyParser interface {
	Parse(logger zerolog.Logger, req RequestBodyParserHTTPRequest, cb ParsedBodyFieldCb) error
	LengthLimits() LengthLimits
}

// RequestBodyParserHTTPRequest represents an HTTP request to be evaluated by RequestBodyParser.
type RequestBodyParserHTTPRequest interface {
	Headers() []HeaderPair
	BodyReader() io.Reader
}

// ContentType of the body field being parsed.
type ContentType int

// ContentTypes available.
const (
	_ ContentType = iota
	MultipartFormDataContent
	URLEncodedContent
	XMLContent
	JSONContent
)

// LengthLimits states limitations we will enforce regarding the lengths of different parts of the request.
type LengthLimits struct {
	MaxLengthField    int // Number of bytes read before returning an error, respecting the PauseCounting flag. The count can be reset whenever a field has been consumed .
	MaxLengthPausable int // Number of bytes read before returning an error, respecting the PauseCounting flag.
	MaxLengthTotal    int // Number of bytes read, ignoring whether the PauseCounting flag was set.
}

// ErrFieldBytesLimitExceeded is returned when the field length limit was exceeded.
var ErrFieldBytesLimitExceeded = errors.New("field length limit exceeded")

// ErrPausableBytesLimitExceeded is returned when the request length limit was exceeded.
var ErrPausableBytesLimitExceeded = errors.New("request length limit exceeded")

// ErrTotalBytesLimitExceeded is returned when the total request length limit was exceeded.
var ErrTotalBytesLimitExceeded = errors.New("total request length limit exceeded")
