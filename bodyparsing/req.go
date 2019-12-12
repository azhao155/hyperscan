package bodyparsing

import (
	"azwaf/waf"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"

	"github.com/rs/zerolog"
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

func (r *reqBodyParserImpl) Parse(
	logger zerolog.Logger,
	bodyReader io.Reader,
	fieldCb waf.ParsedBodyFieldCb,
	reqBodyType waf.ReqBodyType,
	contentLengthOptional int, // Content length if it was already known. 0 is fine if it was not known (transfer-encoding chunked), just slightly less performant.
	multipartBoundary string, // A boundary to use if this is a multipart/form-data body. If this is a different request body type then use "" instead.
	alsoScanFullRawBody bool,

) (err error) {
	// If the headers already up front said that the request is going to be too large, then there is no point in starting to scan the body.
	if contentLengthOptional > r.lengthLimits.MaxLengthTotal {
		err = waf.ErrTotalBytesLimitExceeded
		return
	}

	// Concurrently buffer the full request body if requested to do so.
	fullRequestBodyBuf := bytes.Buffer{}
	if alsoScanFullRawBody {
		// If the headers already up front said that the request is going to be too large, there's no point in starting to scan the body.
		if contentLengthOptional > r.lengthLimits.MaxLengthTotalFullRawRequestBody {
			err = waf.ErrTotalFullRawRequestBodyExceeded
			return
		}

		if contentLengthOptional > 0 {
			fullRequestBodyBuf.Grow(contentLengthOptional)
		}

		bodyReader = io.TeeReader(bodyReader, &fullRequestBodyBuf)
	}

	bodyReaderWithMax := newMaxLengthReaderDecorator(bodyReader, r.lengthLimits, alsoScanFullRawBody)
	// TODO besides these byte count Limits, consider abort if there were too many individual fields

	switch reqBodyType {

	case waf.MultipartFormDataBody:
		err = r.scanMultipartBody(bodyReaderWithMax, multipartBoundary, fieldCb)

	case waf.URLEncodedBody:
		err = r.scanUrlencodedBody(bodyReaderWithMax, fieldCb)

	case waf.XMLBody:
		err = r.scanXMLBody(bodyReaderWithMax, fieldCb)

	case waf.JSONBody:
		// TODO also use for text/json? ModSec currently doesn't...
		// TODO also use for application/javascript JSONP? ModSec currently doesn't...
		err = r.scanJSONBody(bodyReaderWithMax, fieldCb)

	default:
		// Unsupported type of body.
		// TODO consider doing something sensible even for unknown request body types. ModSec doesn't though.

		// Consume entire reader to fill up fullRequestBodyBuf, in case usesFullRawRequestBody was true.
		if alsoScanFullRawBody {
			_, err = io.Copy(ioutil.Discard, bodyReaderWithMax)
		}
	}

	if err != nil {
		if err == waf.ErrFieldBytesLimitExceeded || err == waf.ErrPausableBytesLimitExceeded || err == waf.ErrTotalBytesLimitExceeded {
			return
		}

		err = fmt.Errorf("%v body scanning error: %v", waf.ReqBodyTypeStrings[reqBodyType], err)
		return
	}

	if alsoScanFullRawBody {
		fieldCb(waf.FullRawRequestBody, "", string(fullRequestBodyBuf.Bytes()))
	}

	return
}

func (r *reqBodyParserImpl) scanMultipartBody(bodyReader *maxLengthReaderDecorator, multipartBoundary string, cb waf.ParsedBodyFieldCb) (err error) {
	var buf bytes.Buffer
	m := multipart.NewReader(bodyReader, multipartBoundary)
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

			err = cb(waf.MultipartFormDataFileNames, part.FormName(), cdParams["filename"])
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
