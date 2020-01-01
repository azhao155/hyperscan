package waf

import (
	"errors"
	"io"
	"mime"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
)

// ParsedBodyFieldCb is will be called for each parsed field.
type ParsedBodyFieldCb = func(contentType FieldContentType, fieldName string, data string) error

// RequestBodyParser parses HTTP request bodies.
type RequestBodyParser interface {
	Parse(
		logger zerolog.Logger,
		bodyReader io.Reader,
		fieldCb ParsedBodyFieldCb,
		reqBodyType ReqBodyType,
		contentLengthOptional int, // Content length if it was already known. 0 is fine if it was not known (transfer-encoding chunked), just slightly less performant.
		multipartBoundary string, // A boundary to use if this is a multipart/form-data body. If this is a different request body type then use "" instead.
		alsoScanFullRawBody bool,
	) error
	LengthLimits() LengthLimits
}

// FieldContentType states the type of the body field just scanned.
type FieldContentType int

// FieldContentTypes available.
const (
	_ FieldContentType = iota
	FullRawRequestBody
	MultipartFormDataContent
	MultipartFormDataFileNames
	URLEncodedContent
	XMLContent
	JSONContent
)

// ReqBodyType states what to treat the request body content as.
type ReqBodyType int

// ReqBodyTypes available.
const (
	OtherBody ReqBodyType = iota
	MultipartFormDataBody
	URLEncodedBody
	XMLBody
	JSONBody
	_lastReqBodyTypes
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

// ReqBodyTypeStrings maps from a ReqBodyType to a content-type string.
var ReqBodyTypeStrings = []string{
	"",
	"multipart/form-data",
	"application/x-www-form-urlencoded",
	"text/xml",
	"application/json",
}

func getLengthAndTypeFromHeaders(req HTTPRequest) (contentLength int, reqBodyType ReqBodyType, multipartBoundary string, err error) {
	// TODO consider using DetectContentType instead of the Content-Type field. ModSec only uses Content-Type though.

	for _, h := range req.Headers() {
		k := h.Key()
		v := h.Value()

		if strings.EqualFold("content-length", k) {
			// Ignore error at this point to let CRS rule 920160 do its work.
			contentLength, _ = strconv.Atoi(v)
		}

		if strings.EqualFold("content-type", k) {
			s, mediaTypeParams, _ := mime.ParseMediaType(v)

			reqBodyType = OtherBody
			s = strings.ToLower(s)
			s = strings.TrimSpace(s)
			if s == "multipart/form-data" {
				reqBodyType = MultipartFormDataBody
			} else if s == "application/x-www-form-urlencoded" {
				reqBodyType = URLEncodedBody
			} else if s == "application/json" {
				reqBodyType = JSONBody
			} else if strings.Contains(s, "application/soap+xml") || // These conditions are equivalent to rule 200000 in modsecurity.conf-recommended
				strings.Contains(s, "application/xml") ||
				strings.Contains(s, "text/xml") {
				reqBodyType = XMLBody
			}

			if reqBodyType == MultipartFormDataBody {
				multipartBoundary = mediaTypeParams["boundary"]
			}
		}
	}

	return
}
