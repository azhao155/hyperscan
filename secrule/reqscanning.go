package secrule

import (
	"azwaf/waf"
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// ReqScanner can create NewReqScannerEvaluations, which scans requests for string matches and other properties that the rule engine will be needing to do rule evaluation.
type ReqScanner interface {
	NewReqScannerEvaluation(scratchSpace *ReqScannerScratchSpace) ReqScannerEvaluation
	NewScratchSpace() (scratchSpace *ReqScannerScratchSpace, err error)
}

// ReqScannerEvaluation is a session of the ReqScanner.
type ReqScannerEvaluation interface {
	ScanHeaders(req waf.HTTPRequest) (results *ScanResults, err error)
	ScanBodyField(contentType waf.ContentType, fieldName string, data string, results *ScanResults) error
}

// RxMatch represents a regex match found while scanning.
type RxMatch struct {
	StartPos int
	EndPos   int
	Data     []byte
}

// ScanResults is the collection of all results found while scanning.
type ScanResults struct {
	rxMatches      map[rxMatchKey]RxMatch
	targetsPresent map[string]bool
}

// ReqScannerFactory creates ReqScanners. This makes mocking possible when testing.
type ReqScannerFactory interface {
	NewReqScanner(statements []Statement) (r ReqScanner, err error)
}

// NewReqScannerFactory creates a ReqScannerFactory. The ReqScanners it will create will use multi-regex engines created by the given MultiRegexEngineFactory.
func NewReqScannerFactory(m MultiRegexEngineFactory) ReqScannerFactory {
	return &reqScannerFactoryImpl{m}
}

// ReqScannerScratchSpace is a collection of all the scratch spaces a ReqScanner will need. These can be reused for different requests, but cannot be shared concurrently.
type ReqScannerScratchSpace map[*MultiRegexEngine]MultiRegexEngineScratchSpace

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

type detectXSSGroup struct {
	transformations []Transformation
	backRefs        []patternRef
}

type reqScannerImpl struct {
	scanPatterns      map[string][]*scanGroup
	detectXSSPatterns map[string][]*detectXSSGroup
}

type reqScannerEvaluationImpl struct {
	reqScanner   *reqScannerImpl
	scratchSpace *ReqScannerScratchSpace
}

// NewReqScanner creates a ReqScanner.
func (f *reqScannerFactoryImpl) NewReqScanner(statements []Statement) (r ReqScanner, err error) {
	scanPatterns := make(map[string][]*scanGroup)
	detectXSSPatterns := make(map[string][]*detectXSSGroup)

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
				t := target.toModSecFormat()

				curScanTargets := scanPatterns[t]

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
					scanPatterns[t] = append(scanPatterns[t], curScanGroup)
				}

				p := patternRef{curRule, curRuleItem, curRuleItemIdx}

				switch curRuleItem.Predicate.Op {
				case Rx, Pm, Pmf, PmFromFile, BeginsWith, EndsWith, Contains, ContainsWord, Streq, Strmatch, Within:
					// The value can have macros that cannot be expanded at this time.
					if len(curRuleItem.Predicate.valMacroMatches) == 0 {
						curScanGroup.patterns = append(curScanGroup.patterns, p)
					}
				case DetectXSS:
					curXSSGroup := &detectXSSGroup{}
					curXSSGroup.transformations = curRuleItem.Transformations
					curXSSGroup.backRefs = append(curXSSGroup.backRefs, p)
					detectXSSPatterns[t] = append(detectXSSPatterns[t], curXSSGroup)
				}
			}
		}
	}

	// Construct multi regex engine instances from the scan patterns.
	for target, scanGroups := range scanPatterns {
		for scanGroupIdx, scanGroup := range scanGroups {
			if len(scanGroup.patterns) == 0 {
				// TODO if scanPatterns only holds regex-based scan groups, then this should never happen
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

	r = &reqScannerImpl{
		scanPatterns:      scanPatterns,
		detectXSSPatterns: detectXSSPatterns,
	}

	return
}

func (r *reqScannerImpl) NewReqScannerEvaluation(scratchSpace *ReqScannerScratchSpace) ReqScannerEvaluation {
	return &reqScannerEvaluationImpl{
		reqScanner:   r,
		scratchSpace: scratchSpace,
	}
}

// NewScratchSpace creates an instance of all the scratch spaces this ReqScanner will need.
func (r *reqScannerImpl) NewScratchSpace() (scratchSpace *ReqScannerScratchSpace, err error) {
	s := make(ReqScannerScratchSpace)
	for _, scanGroups := range r.scanPatterns {
		for _, scanGroup := range scanGroups {
			if scanGroup.rxEngine == nil {
				// Happens with scan groups with no patterns
				// TODO if scanPatterns only holds regex-based scan groups, then this should never happen
				continue
			}

			s[&scanGroup.rxEngine], err = scanGroup.rxEngine.CreateScratchSpace()
			if err != nil {
				return
			}
		}
	}

	scratchSpace = &s
	return
}

// Close frees all scratch spaces this ReqScannerScratchSpace held.
func (s ReqScannerScratchSpace) Close() {
	for _, v := range s {
		v.Close()
	}
}

func (r *reqScannerEvaluationImpl) ScanHeaders(req waf.HTTPRequest) (results *ScanResults, err error) {
	results = &ScanResults{
		rxMatches:      make(map[rxMatchKey]RxMatch),
		targetsPresent: make(map[string]bool),
	}

	// We currently don't actually have the raw request line, because it's been parsed by Nginx and send in a struct to us.
	// TODO consider passing the raw request line from Nginx if available.
	var reqLine bytes.Buffer
	reqLine.WriteString(req.Method())
	reqLine.WriteString(" ")
	reqLine.WriteString(req.URI())
	reqLine.WriteString(" HTTP/1.1") // TODO pass actual HTTP version through.
	err = r.scanTarget("REQUEST_LINE", reqLine.String(), results)
	if err != nil {
		return
	}

	err = r.scanTarget("REMOTE_ADDR", req.RemoteAddr(), results)
	if err != nil {
		return
	}

	err = r.scanTarget("REQUEST_METHOD", req.Method(), results)
	if err != nil {
		return
	}

	err = r.scanURI(req.URI(), results)
	if err != nil {
		return
	}

	headers := req.Headers()
	for _, h := range headers {
		k := h.Key()
		v := h.Value()

		if strings.EqualFold(k, "cookie") {
			r.scanCookies(v, results)
		}

		err = r.scanTarget("REQUEST_HEADERS_NAMES", k, results)
		if err != nil {
			return
		}

		err = r.scanTarget("REQUEST_HEADERS", v, results)
		if err != nil {
			return
		}

		// TODO selector probably should not be case sensitive
		err = r.scanTarget("REQUEST_HEADERS:"+k, v, results)
		if err != nil {
			return
		}

	}

	return
}

func (r *reqScannerEvaluationImpl) ScanBodyField(contentType waf.ContentType, fieldName string, data string, results *ScanResults) (err error) {
	// TODO pass on certain content types that modsec doesnt handle?

	switch contentType {

	case waf.MultipartFormDataContent, waf.URLEncodedContent:
		err = r.scanTarget("ARGS_NAMES", fieldName, results)
		if err != nil {
			return
		}

		err = r.scanTarget("ARGS", data, results)
		if err != nil {
			return
		}

		err = r.scanTarget("ARGS:"+fieldName, data, results)
		if err != nil {
			return
		}

		err = r.scanTarget("ARGS_POST", data, results)
		if err != nil {
			return
		}

		err = r.scanTarget("ARGS_POST:"+fieldName, data, results)
		if err != nil {
			return
		}

	case waf.XMLContent, waf.JSONContent:
		err = r.scanTarget("XML:/*", data, results)
		if err != nil {
			return
		}

	default:
		// TODO consider doing something sensible even for unknown request body types. ModSec doesn't though.

	}

	// TODO handle regex selectors and other types of selectors

	return
}

// GetRxResultsFor returns any results for regex matches that were done during the request scanning.
func (r *ScanResults) GetRxResultsFor(ruleID int, ruleItemIdx int, target Target) (m RxMatch, ok bool) {
	// TODO Remove this conversion back to string when regex selectors are fully supported by using Target as part of the key in r.rxMatches
	targetStr := target.toModSecFormat()

	m, ok = r.rxMatches[rxMatchKey{ruleID: ruleID, ruleItemIdx: ruleItemIdx, target: targetStr}]
	return
}

func (r *reqScannerEvaluationImpl) scanTarget(targetName string, content string, results *ScanResults) (err error) {
	// TODO cache if a scan was already done for a given piece of content (consider Murmur hash: https://github.com/twmb/murmur3) and target name, and save time by skipping transforming and scanning it in that case. This could happen with repetitive JSON or XML bodies for example.
	// TODO this cache could even persist across requests, with some LRU purging approach. We could even hash and cache entire request bodies. Wow.

	results.targetsPresent[targetName] = true

	// TODO look up in scanPatterns not only based on full target names, but also based on selectors with regexes
	for _, sg := range r.reqScanner.scanPatterns[targetName] {
		if len(sg.patterns) == 0 {
			continue
		}

		contentTransformed := applyTransformations(content, sg.transformations)

		scratchSpace := (*r.scratchSpace)[&sg.rxEngine]

		var matches []MultiRegexEngineMatch
		matches, err = sg.rxEngine.Scan([]byte(contentTransformed), scratchSpace)
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

	for _, sg := range r.reqScanner.detectXSSPatterns[targetName] {

		contentTransformed := applyTransformations(content, sg.transformations)

		var match bool
		match, _, err = detectXSSOperatorEval(contentTransformed, "")
		if err != nil {
			return
		}

		if match {
			for _, p := range sg.backRefs {

				// Store the match for fast retrieval in the eval phase
				key := rxMatchKey{p.rule.ID, p.ruleItemIdx, targetName}
				if _, alreadyFound := results.rxMatches[key]; !alreadyFound {
					results.rxMatches[key] = RxMatch{
						StartPos: 0,
						EndPos:   0,
						Data:     []byte{},
					}
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
			phrases = append(phrases, "(?i:"+regexp.QuoteMeta(p)+")")
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

func (r *reqScannerEvaluationImpl) scanURI(URI string, results *ScanResults) (err error) {
	err = r.scanTarget("REQUEST_URI", URI, results)
	if err != nil {
		return
	}

	err = r.scanTarget("REQUEST_URI_RAW", URI, results)
	if err != nil {
		return
	}

	// The "filename" is the part before the question mark.
	// Not using url.ParseRequestURI, because REQUEST_FILENAME should be raw, and not URL-decoded.
	reqFilename := URI
	n := strings.IndexByte(URI, '?')
	if n != -1 {
		reqFilename = URI[:n]
	}

	err = r.scanTarget("REQUEST_FILENAME", reqFilename, results)
	if err != nil {
		return
	}

	var uriParsed *url.URL
	uriParsed, err = url.ParseRequestURI(URI)
	if err != nil {
		return
	}

	err = r.scanTarget("QUERY_STRING", uriParsed.RawQuery, results)
	if err != nil {
		return
	}

	var qvals url.Values
	qvals, err = parseQuery(uriParsed.RawQuery)
	if err != nil {
		return
	}

	for k, vv := range qvals {
		err = r.scanTarget("ARGS_NAMES", k, results)
		if err != nil {
			return
		}

		for _, v := range vv {
			err = r.scanTarget("ARGS", v, results)
			if err != nil {
				return
			}

			err = r.scanTarget("ARGS:"+k, v, results)
			if err != nil {
				return
			}
		}
	}

	return
}

func (r *reqScannerEvaluationImpl) scanCookies(c string, results *ScanResults) (err error) {
	// Use Go's http.Request to parse the cookies.
	goReq := &http.Request{Header: http.Header{"Cookie": []string{c}}}
	cookies := goReq.Cookies()
	for _, cookie := range cookies {

		err = r.scanTarget("REQUEST_COOKIES_NAMES", cookie.Name, results)
		if err != nil {
			return
		}

		err = r.scanTarget("REQUEST_COOKIES", cookie.Value, results)
		if err != nil {
			return
		}

		err = r.scanTarget("REQUEST_COOKIES:"+cookie.Name, cookie.Value, results)
		if err != nil {
			return
		}
	}

	return
}

// Similar to url.ParseQuery, but does not consider semicolon as a delimiter. ModSecurity also does not consider semicolon a delimiter.
func parseQuery(query string) (values url.Values, err error) {
	values = make(url.Values)
	for _, arg := range strings.Split(query, "&") {
		var key, val string

		eqPos := strings.IndexByte(arg, '=')
		if eqPos != -1 {
			key, err = url.QueryUnescape(arg[:eqPos])
			if err != nil {
				// TODO consider whether we should tolerate errors here and instead the SecRule's to do their work. Perhaps do something similar to jsUnescape() to best-effort handle URL-decoding and ignore errors.
				return
			}

			if eqPos+1 < len(arg) {
				val, err = url.QueryUnescape(arg[eqPos+1:])
				if err != nil {
					return
				}
			}
		} else {
			key, err = url.QueryUnescape(arg)
			if err != nil {
				return
			}
		}

		values.Add(key, val)
	}

	return
}

func (t *Target) toModSecFormat() string {
	s := t.Name
	if t.Selector != "" {
		s += ":" + t.Selector
	}
	return s
}
