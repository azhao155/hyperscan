package secrule

import (
	"azwaf/waf"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// ReqScanner scans requests for string matches and other properties that the rule engine will be needing to do rule evaluation.
type ReqScanner interface {
	Scan(req waf.HTTPRequest) (results *ScanResults, err error)
	LengthLimits() LengthLimits
}

// RxMatch represents a regex match found while scanning.
type RxMatch struct {
	StartPos int
	EndPos   int
	Data     []byte
}

// ScanResults is the collection of all results found while scanning.
type ScanResults struct {
	rxMatches map[rxMatchKey]RxMatch
}

// ReqScannerFactory creates ReqScanners. This makes mocking possible when testing.
type ReqScannerFactory interface {
	NewReqScanner(statements []Statement) (r ReqScanner, err error)
}

// NewReqScannerFactory creates a ReqScannerFactory. The ReqScanners it will create will use multi-regex engines created by the given MultiRegexEngineFactory.
func NewReqScannerFactory(m MultiRegexEngineFactory) ReqScannerFactory {
	return &reqScannerFactoryImpl{m}
}

type reqScannerFactoryImpl struct {
	multiRegexEngineFactory MultiRegexEngineFactory
}

type rxMatchKey struct {
	ruleID      int
	ruleItemIdx int
	target      string
}

type patternRef struct {
	rule        *Rule
	ruleItem    *RuleItem
	ruleItemIdx int
}

type scanGroup struct {
	transformations []Transformation
	patterns        []patternRef
	rxEngine        MultiRegexEngine
	backRefs        []patternRef
}

type reqScannerImpl struct {
	scanPatterns map[string][]*scanGroup
	lengthLimits LengthLimits
}

// NewReqScanner creates a ReqScanner.
func (f *reqScannerFactoryImpl) NewReqScanner(statements []Statement) (r ReqScanner, err error) {
	scanPatterns := make(map[string][]*scanGroup)

	// Construct a inverted view of the rules that maps from targets to rules
	for _, curStmt := range statements {
		curRule, ok := curStmt.(*Rule)
		if !ok {
			// This statement was not a rule
			continue
		}

		for curRuleItemIdx := range curRule.Items {
			curRuleItem := &curRule.Items[curRuleItemIdx]
			for _, target := range curRuleItem.Predicate.Targets {
				curScanTargets := scanPatterns[target]

				// This target can have multiple different transformations. Find the right one or create one.
				var curScanGroup *scanGroup
				for _, sp := range curScanTargets {
					if transformationListEquals(sp.transformations, curRuleItem.Transformations) {
						curScanGroup = sp
					}
				}
				if curScanGroup == nil {
					// This is the first time we see a RuleItem for this ARG with this transformation pipeline, so we'll create a scanGroup object for it.
					curScanGroup = &scanGroup{transformations: curRuleItem.Transformations}
					scanPatterns[target] = append(scanPatterns[target], curScanGroup)
				}

				switch curRuleItem.Predicate.Op {
				case Rx, Pm, Pmf, PmFromFile, BeginsWith, EndsWith, Contains, ContainsWord, Streq, Strmatch, Within:
					// The value can have macros that cannot be expanded at this time.
					if len(curRuleItem.Predicate.valMacroMatches) == 0 {
						p := patternRef{curRule, curRuleItem, curRuleItemIdx}
						curScanGroup.patterns = append(curScanGroup.patterns, p)
					}
				}
			}
		}
	}

	// Construct multi regex engine instances from the scan patterns.
	for target, scanGroups := range scanPatterns {
		for scanGroupIdx, scanGroup := range scanGroups {
			if len(scanGroup.patterns) == 0 {
				continue
			}

			// When the multi regex engine finds a match, it gives us a single ID. BackRefs gets us from the ID to the actual rule.
			backRefs := []patternRef{}
			backRefCurID := 0

			patterns := []MultiRegexEnginePattern{}
			for _, p := range scanGroup.patterns {
				exprs := getRxExprs(p.ruleItem)
				for _, e := range exprs {
					// This will allow us to navigate back to the actual rule when the multi scan engine finds a match.
					backRefs = append(backRefs, p)
					patterns = append(patterns, MultiRegexEnginePattern{backRefCurID, e})
					backRefCurID++
				}
			}

			scanPatterns[target][scanGroupIdx].backRefs = backRefs

			scanPatterns[target][scanGroupIdx].rxEngine, err = f.multiRegexEngineFactory.NewMultiRegexEngine(patterns)
			if err != nil {
				err = fmt.Errorf("failed to create multi-regex engine: %v", err)
				return
			}
		}
	}

	lengthLimits := LengthLimits{
		MaxLengthField:    1024 * 20,         // 20 KiB
		MaxLengthPausable: 1024 * 128,        // 128 KiB
		MaxLengthTotal:    1024 * 1024 * 700, // 700 MiB
	}

	r = &reqScannerImpl{
		scanPatterns: scanPatterns,
		lengthLimits: lengthLimits,
	}

	return
}

func (r *reqScannerImpl) Scan(req waf.HTTPRequest) (results *ScanResults, err error) {
	results = &ScanResults{
		rxMatches: make(map[rxMatchKey]RxMatch),
	}

	err = r.scanURI(req.URI(), results)
	if err != nil {
		return
	}

	contentType, contentLength, err := r.scanHeaders(req.Headers(), results)
	if err != nil {
		return
	}

	// If the headers already up front said that the request is going to be too large, there's no point in starting to scan the body.
	if contentLength > r.lengthLimits.MaxLengthTotal {
		err = errTotalBytesLimitExceeded
		return
	}

	bodyReader := req.BodyReader()
	bodyReaderWithMax := newMaxLengthReaderDecorator(bodyReader, r.lengthLimits)
	// TODO besides these byte count Limits, consider abort if there were too many individual fields

	// TODO consider using DetectContentType instead of the Content-Type field. ModSec only uses Content-Type though.
	mediatype, mediaTypeParams, _ := mime.ParseMediaType(contentType)

	switch mediatype {

	case "multipart/form-data":
		err = r.scanMultipartBody(bodyReaderWithMax, mediaTypeParams, results)

	case "application/x-www-form-urlencoded":
		err = r.scanUrlencodedBody(bodyReaderWithMax, results)

	case "text/xml":
		err = r.scanXMLBody(bodyReaderWithMax, results)

	case "application/json":
		// TODO also use for text/json? ModSec currently doesn't...
		// TODO also use for application/javascript JSONP? ModSec currently doesn't...
		err = r.scanJSONBody(bodyReaderWithMax, results)

	default:
		// Unsupported type of body. Not scanning for now.
		// TODO consider doing something sensible even for unknown request body types. ModSec doesn't though.
	}

	if err != nil {
		if err == errFieldBytesLimitExceeded || err == errPausableBytesLimitExceeded || err == errTotalBytesLimitExceeded {
			return
		}

		err = fmt.Errorf("%v body scanning error: %v", mediatype, err)
		return
	}

	return
}

func (r *reqScannerImpl) LengthLimits() LengthLimits {
	return r.lengthLimits
}

// GetRxResultsFor returns any results for regex matches that were done during the request scanning.
func (r *ScanResults) GetRxResultsFor(ruleID int, ruleItemIdx int, target string) (m RxMatch, ok bool) {
	m, ok = r.rxMatches[rxMatchKey{ruleID: ruleID, ruleItemIdx: ruleItemIdx, target: target}]
	return
}

func (r *reqScannerImpl) scanTarget(targetName string, content string, results *ScanResults) (err error) {
	// TODO cache if a scan was already done for a given piece of content (consider Murmur hash: https://github.com/twmb/murmur3) and target name, and save time by skipping transforming and scanning it in that case. This could happen with repetitive JSON or XML bodies for example.
	// TODO this cache could even persist across requests, with some LRU purging approach. We could even hash and cache entire request bodies. Wow.

	// TODO look up in scanPatterns not only based on full target names, but also based on selectors with regexes
	for _, sg := range r.scanPatterns[targetName] {
		if len(sg.patterns) == 0 {
			continue
		}

		contentTransformed := applyTransformations(content, sg.transformations)

		var matches []MultiRegexEngineMatch
		matches, err = sg.rxEngine.Scan([]byte(contentTransformed))
		if err != nil {
			return
		}

		for _, m := range matches {
			p := sg.backRefs[m.ID]

			// Store the match for fast retrieval in the eval phase
			key := rxMatchKey{p.rule.ID, p.ruleItemIdx, targetName}
			if _, alreadyFound := results.rxMatches[key]; !alreadyFound {
				results.rxMatches[key] = RxMatch{
					StartPos: m.StartPos,
					EndPos:   m.EndPos,
					Data:     m.Data,
				}
			}
		}
	}

	return
}

func getRxExprs(ruleItem *RuleItem) []string {
	v := regexp.QuoteMeta(ruleItem.Predicate.Val)
	switch ruleItem.Predicate.Op {
	case Rx:
		return []string{ruleItem.Predicate.Val}
	case Pm, Pmf, PmFromFile:
		var phrases []string
		for _, p := range ruleItem.PmPhrases {
			phrases = append(phrases, regexp.QuoteMeta(p))
		}
		return phrases
	case BeginsWith:
		return []string{"^" + v}
	case EndsWith:
		return []string{v + "$"}
	case Contains, Strmatch:
		return []string{v}
	case ContainsWord:
		return []string{`\b` + v + `\b`}
	case Streq:
		return []string{"^" + v + "$"}
	case Within:
		var words []string
		var parameterStrings = strings.Split(ruleItem.Predicate.Val, " ")
		for _, p := range parameterStrings {
			words = append(words, "^"+regexp.QuoteMeta(p)+"$")
		}
		return words
	}

	return nil
}

func (r *reqScannerImpl) scanHeaders(headers []waf.HeaderPair, results *ScanResults) (contentType string, contentLength int, err error) {
	contentLength = -1

	for _, h := range headers {
		k := h.Key()
		v := h.Value()

		if strings.ToLower(h.Key()) == "content-length" {
			contentLength, err = strconv.Atoi(h.Value())
			if err != nil {
				err = fmt.Errorf("failed to parse Content-Length header")
			}
		}

		if strings.ToLower(h.Key()) == "content-type" {
			contentType = h.Value()
		}

		r.scanTarget("REQUEST_HEADERS", v, results)
		if err != nil {
			return
		}

		r.scanTarget("REQUEST_HEADERS_NAMES", k, results)
		if err != nil {
			return
		}
	}

	return
}

func (r *reqScannerImpl) scanURI(URI string, results *ScanResults) (err error) {
	r.scanTarget("REQUEST_URI_RAW", URI, results)
	if err != nil {
		return
	}

	var uriParsed *url.URL
	uriParsed, err = url.ParseRequestURI(URI)
	if err != nil {
		return
	}

	var qvals url.Values
	qvals, err = url.ParseQuery(uriParsed.RawQuery)
	if err != nil {
		return
	}

	for k, vv := range qvals {
		r.scanTarget("ARGS_NAMES", k, results)
		if err != nil {
			return
		}

		for _, v := range vv {
			r.scanTarget("ARGS", v, results)
			if err != nil {
				return
			}
		}
	}

	return
}

func (r *reqScannerImpl) scanMultipartBody(bodyReader *maxLengthReaderDecorator, mediaTypeParams map[string]string, results *ScanResults) (err error) {
	var buf bytes.Buffer
	m := multipart.NewReader(bodyReader, mediaTypeParams["boundary"])
	for i := 0; ; i++ {
		bodyReader.ResetFieldReadCount() // Even though the part headers are not strictly a "field", they still may be a significant number of bytes, so we'll treat them as a field.
		var part *multipart.Part
		part, err = m.NextPart()
		if err != nil {
			// Unfortunately NextPart() doesn't return the raw err, but wraps it.
			if bodyReader.IsFieldLimitReached() {
				err = errFieldBytesLimitExceeded
				return
			}
			if bodyReader.IsPausableReached() {
				err = errPausableBytesLimitExceeded
				return
			}
			if bodyReader.IsTotalLimitReached() {
				err = errTotalBytesLimitExceeded
				return
			}

			if err == io.EOF {
				err = nil
				break
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
			continue
		}

		bodyReader.PauseCounting = false

		err = r.scanTarget("ARGS_NAMES", part.FormName(), results)
		if err != nil {
			return
		}

		bodyReader.ResetFieldReadCount()
		buf.Reset()
		_, err = buf.ReadFrom(part)
		if err != nil {
			if err == errFieldBytesLimitExceeded || err == errPausableBytesLimitExceeded || err == errTotalBytesLimitExceeded {
				return
			}

			err = fmt.Errorf("body parsing error while reading part content: %v", err)
			return
		}

		s := string(buf.Bytes())
		r.scanTarget("ARGS", s, results)
		if err != nil {
			return
		}
	}

	return
}

func (r *reqScannerImpl) scanUrlencodedBody(bodyReader *maxLengthReaderDecorator, results *ScanResults) (err error) {
	// TODO remove this line, and instead implement a urlencode parser that uses the io.Reader interface, so we can call body bodyReader.ResetFieldReadCount() after reading each field
	bodyReader.Limits.MaxLengthField = bodyReader.Limits.MaxLengthPausable

	var buf bytes.Buffer
	_, err = buf.ReadFrom(bodyReader)
	if err != nil {
		if err == errPausableBytesLimitExceeded || err == errTotalBytesLimitExceeded {
			return
		}

		return
	}

	qvals, err := url.ParseQuery(buf.String())
	if err != nil {
		return
	}

	for k, vv := range qvals {
		r.scanTarget("ARGS_NAMES", k, results)
		if err != nil {
			return
		}

		for _, v := range vv {
			r.scanTarget("ARGS", v, results)
			if err != nil {
				return
			}
		}
	}

	return
}

func (r *reqScannerImpl) scanJSONBody(bodyReader *maxLengthReaderDecorator, results *ScanResults) (err error) {
	dec := json.NewDecoder(bodyReader)
	for {
		bodyReader.ResetFieldReadCount()
		var token json.Token
		token, err = dec.Token()
		if err != nil {
			if err == errFieldBytesLimitExceeded || err == errPausableBytesLimitExceeded || err == errTotalBytesLimitExceeded {
				return
			}

			if err == io.EOF {
				err = nil
			}

			return
		}

		// TODO selectors
		// It's odd, but SecRule-lang uses the XML selector to select JSON
		target := "XML:/*"

		// TODO handle float64, Number, bool, nil
		switch v := token.(type) {
		case string:
			r.scanTarget(target, v, results)
		}
	}

	return
}

func (r *reqScannerImpl) scanXMLBody(bodyReader *maxLengthReaderDecorator, results *ScanResults) (err error) {
	dec := xml.NewDecoder(bodyReader)
	for {
		bodyReader.ResetFieldReadCount()
		var token xml.Token
		token, err = dec.Token()
		if err != nil {
			if err == errFieldBytesLimitExceeded || err == errPausableBytesLimitExceeded || err == errTotalBytesLimitExceeded {
				return
			}

			if err == io.EOF {
				err = nil
			}

			return
		}

		// TODO selectors
		target := "XML:/*"

		// TODO consider handing element names, attribute names, attribute values. ModSec currently doesn't...
		switch v := token.(type) {
		case xml.CharData:
			r.scanTarget(target, string(v), results)
		}
	}

	return
}
