package bodyparsing

import (
	"azwaf/waf"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/rs/zerolog"
	"io"
	"mime"
	"mime/multipart"
	"strconv"
	"strings"
)

// NewRequestBodyParser creates a RequestBodyParser.
func NewRequestBodyParser(lengthLimits waf.LengthLimits) waf.RequestBodyParser {
	return &reqBodyParserImpl{
		lengthLimits: lengthLimits,
	}
}

type reqBodyParserImpl struct {
	lengthLimits waf.LengthLimits
}

func (r *reqBodyParserImpl) LengthLimits() waf.LengthLimits {
	return r.lengthLimits
}

func (r *reqBodyParserImpl) Parse(logger zerolog.Logger, req waf.HTTPRequest, cb waf.ParsedBodyFieldCb) (err error) {
	// Find the content-length and content-type
	contentLength, contentType, err := r.getLengthAndTypeFromHeaders(req)
	if err != nil {
		return
	}

	// If the headers already up front said that the request is going to be too large, there's no point in starting to scan the body.
	if contentLength > r.lengthLimits.MaxLengthTotal {
		err = waf.ErrTotalBytesLimitExceeded
		return
	}

	bodyReader := req.BodyReader()
	bodyReaderWithMax := newMaxLengthReaderDecorator(bodyReader, r.lengthLimits)
	// TODO besides these byte count Limits, consider abort if there were too many individual fields

	// TODO consider using DetectContentType instead of the Content-Type field. ModSec only uses Content-Type though.
	mediatype, mediaTypeParams, _ := mime.ParseMediaType(contentType)

	switch mediatype {

	case "multipart/form-data":
		err = r.scanMultipartBody(bodyReaderWithMax, mediaTypeParams, cb)

	case "application/x-www-form-urlencoded":
		err = r.scanUrlencodedBody(bodyReaderWithMax, cb)

	case "text/xml":
		err = r.scanXMLBody(bodyReaderWithMax, cb)

	case "application/json":
		// TODO also use for text/json? ModSec currently doesn't...
		// TODO also use for application/javascript JSONP? ModSec currently doesn't...
		err = r.scanJSONBody(bodyReaderWithMax, cb)

	default:
		// Unsupported type of body. Not scanning for now.
		// TODO consider doing something sensible even for unknown request body types. ModSec doesn't though.
	}

	if err != nil {
		if err == waf.ErrFieldBytesLimitExceeded || err == waf.ErrPausableBytesLimitExceeded || err == waf.ErrTotalBytesLimitExceeded {
			return
		}

		err = fmt.Errorf("%v body scanning error: %v", mediatype, err)
		return
	}

	return
}

func (r *reqBodyParserImpl) getLengthAndTypeFromHeaders(req waf.HTTPRequest) (contentLength int, contentType string, err error) {
	for _, h := range req.Headers() {
		k := h.Key()
		v := h.Value()

		if strings.EqualFold("content-length", k) {
			contentLength, err = strconv.Atoi(v)
			if err != nil {
				err = fmt.Errorf("failed to parse Content-Length header")
				return
			}
		}

		if strings.EqualFold("content-type", k) {
			contentType = v
		}
	}

	return
}

func (r *reqBodyParserImpl) scanMultipartBody(bodyReader *maxLengthReaderDecorator, mediaTypeParams map[string]string, cb waf.ParsedBodyFieldCb) (err error) {
	var buf bytes.Buffer
	m := multipart.NewReader(bodyReader, mediaTypeParams["boundary"])
	done := false
	for i := 0; !done; i++ {
		bodyReader.ResetFieldReadCount() // Even though the part headers are not strictly a "field", they still may be a significant number of bytes, so we'll treat them as a field.
		var part *multipart.Part
		part, err = m.NextPart()
		if err != nil {
			if err == io.EOF {
				err = nil
				return
			}

			// NextPart() doesn't return the raw err, but wraps it. Therefore we must check the state of the underlying reader.
			if bodyReader.LastErr == waf.ErrFieldBytesLimitExceeded || bodyReader.LastErr == waf.ErrPausableBytesLimitExceeded || bodyReader.LastErr == waf.ErrTotalBytesLimitExceeded {
				err = bodyReader.LastErr
				return
			}

			// We allow 0 length bodies
			if bodyReader.LastErr == io.EOF && bodyReader.ReadCountTotal == 0 {
				err = nil
				return
			}

			err = fmt.Errorf("body parsing error while reading part headers: %v", err)
			return
		}

		// Skip parts that are files.
		c := part.Header.Get("Content-Disposition")
		var cdParams map[string]string
		_, cdParams, err = mime.ParseMediaType(c)
		if err != nil {
			err = fmt.Errorf("error while parsing Content-Disposition header of part number %v: %v", i, err)
			return
		}
		if _, ok := cdParams["filename"]; ok {
			// File parts are not scanned.
			// Space for this file part will not be allocated.
			bodyReader.PauseCounting = true

			err = cb(waf.MultipartFormDataContent, part.FormName(), "")
			if err != nil {
				return
			}

			continue
		}

		bodyReader.PauseCounting = false

		bodyReader.ResetFieldReadCount()
		buf.Reset()
		_, err = buf.ReadFrom(part)
		if err != nil {
			if err == waf.ErrFieldBytesLimitExceeded || err == waf.ErrPausableBytesLimitExceeded || err == waf.ErrTotalBytesLimitExceeded {
				return
			}

			err = fmt.Errorf("body parsing error while reading part content: %v", err)
			return
		}

		s := string(buf.Bytes())
		cb(waf.MultipartFormDataContent, part.FormName(), s)
		if err != nil {
			return
		}
	}

	return
}

func (r *reqBodyParserImpl) scanUrlencodedBody(bodyReader *maxLengthReaderDecorator, cb waf.ParsedBodyFieldCb) (err error) {
	dec := newURLDecoder(bodyReader)
	for {
		bodyReader.ResetFieldReadCount()
		var key, value string
		key, value, err = dec.next()
		if err != nil {
			if err == waf.ErrFieldBytesLimitExceeded || err == waf.ErrPausableBytesLimitExceeded || err == waf.ErrTotalBytesLimitExceeded {
				return
			}

			if err == io.EOF {
				err = nil
			}

			return
		}

		cb(waf.URLEncodedContent, key, value)
	}

	return
}

func (r *reqBodyParserImpl) scanJSONBody(bodyReader *maxLengthReaderDecorator, cb waf.ParsedBodyFieldCb) (err error) {
	dec := json.NewDecoder(bodyReader)
	for {
		bodyReader.ResetFieldReadCount()
		var token json.Token
		token, err = dec.Token()
		if err != nil {
			if err == waf.ErrFieldBytesLimitExceeded || err == waf.ErrPausableBytesLimitExceeded || err == waf.ErrTotalBytesLimitExceeded {
				return
			}

			if err == io.EOF {
				err = nil
			}

			return
		}

		// TODO handle float64, Number, bool, nil
		switch v := token.(type) {
		case string:
			// It's odd, but SecRule-lang uses the XML selector to select JSON
			// TODO can this oddity be moved to secrule rather than bodyparsing
			// TODO selectors
			cb(waf.JSONContent, "", v)
		}
	}

	return
}

func (r *reqBodyParserImpl) scanXMLBody(bodyReader *maxLengthReaderDecorator, cb waf.ParsedBodyFieldCb) (err error) {
	dec := xml.NewDecoder(bodyReader)
	for {
		bodyReader.ResetFieldReadCount()
		var token xml.Token
		token, err = dec.Token()
		if err != nil {
			if err == waf.ErrFieldBytesLimitExceeded || err == waf.ErrPausableBytesLimitExceeded || err == waf.ErrTotalBytesLimitExceeded {
				return
			}

			if err == io.EOF {
				err = nil
			}

			return
		}

		// TODO consider handing element names, attribute names, attribute values. ModSec currently doesn't...
		switch v := token.(type) {
		case xml.CharData:
			// TODO selectors
			cb(waf.XMLContent, "", string(v))
		}
	}

	return
}
