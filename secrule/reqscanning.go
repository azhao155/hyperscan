package secrule

import (
	"azwaf/waf"
	"bytes"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ReqScanner scans requests for string matches and other properties that the rule engine will be needing to do rule evaluation.
type ReqScanner interface {
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

	r = &reqScannerImpl{
		scanPatterns: scanPatterns,
	}

	return
}

func (r *reqScannerImpl) ScanHeaders(req waf.HTTPRequest) (results *ScanResults, err error) {
	results = &ScanResults{
		rxMatches: make(map[rxMatchKey]RxMatch),
	}

	// We currently don't actually have the raw request line, because it's been parsed by Nginx and send in a struct to us.
	// TODO consider passing the raw request line from Nginx if available.
	var reqLine bytes.Buffer
	reqLine.WriteString(req.Method())
	reqLine.WriteString(" ")
	reqLine.WriteString(req.URI())
	reqLine.WriteString(" HTTP/1.1") // TODO pass actual HTTP version through.
	r.scanTarget("REQUEST_LINE", reqLine.String(), results)

	err = r.scanURI(req.URI(), results)
	if err != nil {
		return
	}

	headers := req.Headers()
	for _, h := range headers {
		k := h.Key()
		v := h.Value()

		err = r.scanTarget("REQUEST_HEADERS_NAMES", k, results)
		if err != nil {
			return
		}

		err = r.scanTarget("REQUEST_HEADERS", v, results)
		if err != nil {
			return
		}

		err = r.scanTarget("REQUEST_HEADERS:"+k, v, results)
		if err != nil {
			return
		}

	}

	return
}

func (r *reqScannerImpl) ScanBodyField(contentType waf.ContentType, fieldName string, data string, results *ScanResults) (err error) {
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

func (r *reqScannerImpl) scanURI(URI string, results *ScanResults) (err error) {
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
	r.scanTarget("REQUEST_FILENAME", reqFilename, results)
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
