package waf

import (
	"errors"
	"github.com/rs/zerolog"
	"io"
)

// ParsedBodyFieldCb is will be called for each parsed field.
type ParsedBodyFieldCb = func(contentType ContentType, fieldName string, data string) error

// UsesFullRawRequestBodyCb will be called to determine whether to buffer and pass the full raw request body to ParsedBodyFieldCb.
type UsesFullRawRequestBodyCb = func(contentType ContentType) bool

// RequestBodyParser parses HTTP request bodies.
type RequestBodyParser interface {
	Parse(
		logger zerolog.Logger,
		req RequestBodyParserHTTPRequest,
		fieldCb ParsedBodyFieldCb,
		usesFullRawRequestBodyCb UsesFullRawRequestBodyCb,
	) error
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
	FullRawRequestBody
	MultipartFormDataContent
	MultipartFormDataFileNames
	URLEncodedContent
	XMLContent
	JSONContent
)

// LengthLimits states limitations we will enforce regarding the lengths of different parts of the request.
type LengthLimits struct {
	MaxLengthField                   int // Number of bytes read before returning an error, respecting the PauseCounting flag. The count can be reset whenever a field has been consumed .
	MaxLengthPausable                int // Number of bytes read before returning an error, respecting the PauseCounting flag.
	MaxLengthTotal                   int // Number of bytes read before returning an error, ignoring whether the PauseCounting flag was set.
	MaxLengthTotalFullRawRequestBody int // Like MaxLengthTotal, but when in the mode the entire request body is treated as one giant single field.
}

// DefaultLengthLimits are the default length limits that Azwaf will use unless overriden.
var DefaultLengthLimits = LengthLimits{
	MaxLengthField:                   1024 * 20,         // 20 KiB
	MaxLengthPausable:                1024 * 128,        // 128 KiB
	MaxLengthTotal:                   1024 * 1024 * 700, // 700 MiB
	MaxLengthTotalFullRawRequestBody: 1024 * 20,         // 20 KiB
}

// ErrFieldBytesLimitExceeded is returned when the field length limit was exceeded.
var ErrFieldBytesLimitExceeded = errors.New("field length limit exceeded")

// ErrPausableBytesLimitExceeded is returned when the request length limit was exceeded.
var ErrPausableBytesLimitExceeded = errors.New("request length limit exceeded")

// ErrTotalBytesLimitExceeded is returned when the total request length limit was exceeded.
var ErrTotalBytesLimitExceeded = errors.New("total request length limit exceeded")

// ErrTotalFullRawRequestBodyExceeded is returned when the total request length limit exceeded for full raw request body buffering was exceeded.
var ErrTotalFullRawRequestBodyExceeded = errors.New("total request length limit exceeded for full raw request body buffering")
