package secrule

import (
	"azwaf/waf"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ReqScanner scans requests for string matches and other properties that the rule engine will be needing to do rule evaluation.
type ReqScanner interface {
	Scan(req waf.HTTPRequest) (results *ScanResults, err error)
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
}

// NewReqScanner creates a ReqScanner.
func (f *reqScannerFactoryImpl) NewReqScanner(statements []Statement) (r ReqScanner, err error) {
	startTime := time.Now()

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

			log.WithFields(log.Fields{"target": target, "transformations": scanGroup.transformations, "patternCount": len(patterns)}).Debug("Initializing multi-regex engine")

			scanPatterns[target][scanGroupIdx].rxEngine, err = f.multiRegexEngineFactory.NewMultiRegexEngine(patterns)
			if err != nil {
				err = fmt.Errorf("failed to create multi-regex engine: %v", err)
				return
			}
		}
	}

	r = &reqScannerImpl{
		scanPatterns: scanPatterns,
	}

	log.WithFields(log.Fields{"timeTaken": time.Since(startTime)}).Info("Done initializing scan targets")

	return
}

func (r *reqScannerImpl) Scan(req waf.HTTPRequest) (results *ScanResults, err error) {
	results = &ScanResults{
		rxMatches: make(map[rxMatchKey]RxMatch),
	}

	log.Debug("Scanning URI")
	err = r.scanURI(req.URI(), results)
	if err != nil {
		return
	}

	log.Debug("Scanning headers")
	contentType, err := r.scanHeaders(req.Headers(), results)
	if err != nil {
		return
	}

	bodyReader := req.BodyReader()

	// TODO consider using DetectContentType instead of the Content-Type field. ModSec only uses Content-Type though.
	mediatype, mediaTypeParams, _ := mime.ParseMediaType(contentType)
	switch mediatype {
	case "multipart/form-data":
		log.Debug("Using multipart parser")
		err = r.scanMultipartBody(bodyReader, mediaTypeParams, results)
		if err != nil {
			err = fmt.Errorf("multipart body scanning error: %v", err)
			return
		}

	case "application/x-www-form-urlencoded":
		log.Debug("Using urlencoded parser")
		err = r.scanUrlencodedBody(bodyReader, results)
		if err != nil {
			err = fmt.Errorf("urlencoded body scanning error: %v", err)
			return
		}

	case "text/xml":
		log.Debug("Using XML parser")
		err = r.scanXMLBody(bodyReader, results)
		if err != nil {
			err = fmt.Errorf("XML body scanning error: %v", err)
			return
		}

	case "application/json":
		// TODO also use for text/json? ModSec currently doesn't...
		// TODO also use for application/javascript JSONP? ModSec currently doesn't...
		log.Debug("Using JSON parser")
		err = r.scanJSONBody(bodyReader, results)
		if err != nil {
			err = fmt.Errorf("JSON body scanning error: %v", err)
			return
		}

	}

	return
}

// GetRxResultsFor returns any results for regex matches that were done during the request scanning.
func (r *ScanResults) GetRxResultsFor(ruleID int, ruleItemIdx int, target string) (m RxMatch, ok bool) {
	m, ok = r.rxMatches[rxMatchKey{ruleID: ruleID, ruleItemIdx: ruleItemIdx, target: target}]
	return
}

func (r *reqScannerImpl) scanTarget(targetName string, content string, results *ScanResults) (err error) {
	// TODO cache if a scan was already done for a given piece of content (consider Murmur hash: https://github.com/twmb/murmur3) and target name, and save time by skipping transforming and scanning it in that case. This could happen with repetitive JSON or XML bodies for example.
	// TODO this cache could even persist across requests, with some LRU purging approach. We could even hash and cache entire request bodies. Wow.

	log.WithFields(log.Fields{"targetName": targetName, "content": content}).Trace("Starting target content scan")

	// TODO look up in scanPatterns not only based on full target names, but also based on selectors with regexes
	for _, sg := range r.scanPatterns[targetName] {
		if len(sg.patterns) == 0 {
			continue
		}

		contentTransformed := applyTransformations(content, sg.transformations)

		log.WithFields(log.Fields{"contentOrig": content, "contentTransformed": contentTransformed, "transformations": sg.transformations}).Trace("Scanning transformed content")

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

func (r *reqScannerImpl) scanHeaders(headers []waf.HeaderPair, results *ScanResults) (contentType string, err error) {
	for _, h := range headers {
		k := h.Key()
		v := h.Value()

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

func (r *reqScannerImpl) scanMultipartBody(bodyReader io.Reader, mediaTypeParams map[string]string, results *ScanResults) (err error) {
	var buf bytes.Buffer
	m := multipart.NewReader(bodyReader, mediaTypeParams["boundary"])
	for i := 0; ; i++ {
		log.WithFields(log.Fields{"partNumber": i}).Trace("Getting next multipart part")

		var part *multipart.Part
		part, err = m.NextPart()
		if err != nil {
			if err == io.EOF {
				err = nil
				break
			}
			err = fmt.Errorf("parsing error: %v", err)
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
			log.WithFields(log.Fields{"partNumber": i}).Trace("Skipping file part")
			continue
		}

		r.scanTarget("ARGS_NAMES", part.FormName(), results)
		if err != nil {
			return
		}

		buf.Reset()
		// TODO implement custom ReadFrom which stops and throws err when it reaches some max field length
		_, err = buf.ReadFrom(part)
		if err != nil {
			err = fmt.Errorf("body parsing error: %v", err)
			return
		}

		s := string(buf.Bytes())
		r.scanTarget("ARGS", s, results)
		if err != nil {
			return
		}

		// TODO abort if there were too many fields
	}

	return
}

func (r *reqScannerImpl) scanUrlencodedBody(bodyReader io.Reader, results *ScanResults) (err error) {
	var buf bytes.Buffer
	_, err = buf.ReadFrom(bodyReader)
	if err != nil {
		return
	}

	// TODO don't use url.ParseQuery here. This is vulnerable to DoS by for example posting a gigabyte request body. Instead implement a streaming parser that takes an io.Reader. The source code of the current ParseQuery is only about 30 lines, so it should be easy.
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

			// TODO abort if there were too many fields
		}
	}

	return
}

func (r *reqScannerImpl) scanJSONBody(bodyReader io.Reader, results *ScanResults) (err error) {
	dec := json.NewDecoder(bodyReader)
	for {
		// TODO enforce a max for high large fields may be
		var token json.Token
		token, err = dec.Token()
		if err != nil {
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

		// TODO abort if there were too many fields
	}

	return
}

func (r *reqScannerImpl) scanXMLBody(bodyReader io.Reader, results *ScanResults) (err error) {
	dec := xml.NewDecoder(bodyReader)
	for {
		// TODO enforce a max for high large fields may be
		var token xml.Token
		token, err = dec.Token()
		if err != nil {
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

		// TODO abort if there were too many fields
	}

	return
}
