package secrule

import (
	"azwaf/waf"
	"fmt"
	"log"
	"net/url"
	"regexp"
)

// ReqScanner scans requests for string matches and other properties that the rule engine will be needing to do rule evaluation.
type ReqScanner interface {
	Scan(req waf.HTTPRequest) (results ScanResults, err error)
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
	NewReqScanner(rules []Rule) (r ReqScanner, err error)
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
}

type reqScannerImpl struct {
	scanPatterns map[string][]*scanGroup
	backRefs     []patternRef
}

// NewReqScanner creates a ReqScanner.
func (f *reqScannerFactoryImpl) NewReqScanner(rules []Rule) (r ReqScanner, err error) {
	scanPatterns := make(map[string][]*scanGroup)

	// Construct a inverted view of the rules that maps from targets to rules
	for curRuleIdx := range rules {
		curRule := &rules[curRuleIdx]
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
				case Rx, Pmf, PmFromFile:
					p := patternRef{curRule, curRuleItem, curRuleItemIdx}
					curScanGroup.patterns = append(curScanGroup.patterns, p)
				}
			}
		}
	}

	// When the multi regex engine finds a match, it gives us a single ID. BackRefs gets us from the ID to the actual rule.
	backRefs := []patternRef{}
	backRefCurID := 0

	// Construct multi regex engine instances from the scan patterns.
	for target, scanGroups := range scanPatterns {
		for scanGroupIdx, scanGroup := range scanGroups {
			if len(scanGroup.patterns) == 0 {
				continue
			}

			patterns := []MultiRegexEnginePattern{}
			for _, p := range scanGroup.patterns {
				// This will allow us to navigate back to the actual rule when the multi scan engine finds a match.
				backRefs = append(backRefs, p)

				exprs := getRxExprs(p.ruleItem)
				for _, e := range exprs {
					patterns = append(patterns, MultiRegexEnginePattern{backRefCurID, e})
					backRefCurID++
				}
			}

			log.Printf("Building multi-regex database for target %v with transformations %v with %d patterns", target, scanGroup.transformations, len(patterns))
			scanPatterns[target][scanGroupIdx].rxEngine, err = f.multiRegexEngineFactory.NewMultiRegexEngine(patterns)
			if err != nil {
				err = fmt.Errorf("failed to create multi-regex engine: %v", err)
				return
			}
		}
	}

	r = &reqScannerImpl{
		scanPatterns: scanPatterns,
		backRefs:     backRefs,
	}

	return
}

func getRxExprs(ruleItem *RuleItem) []string {
	switch ruleItem.Predicate.Op {
	case Rx:
		return []string{ruleItem.Predicate.Val}
	case Pmf, PmFromFile:
		var phrases []string
		for _, p := range ruleItem.PmPhrases {
			phrases = append(phrases, regexp.QuoteMeta(p))
		}
		return phrases
	}
	return nil
}

func (r *reqScannerImpl) Scan(req waf.HTTPRequest) (results ScanResults, err error) {
	results.rxMatches = make(map[rxMatchKey]RxMatch)

	r.scanTarget("REQUEST_URI_RAW", req.URI(), &results)
	if err != nil {
		// TODO handle scan error
		return
	}

	var uriParsed *url.URL
	uriParsed, err = url.ParseRequestURI(req.URI())
	if err != nil {
		// TODO handle parse error
		return
	}

	var qvals url.Values
	qvals, err = url.ParseQuery(uriParsed.RawQuery)
	if err != nil {
		// TODO handle parse error
		return
	}

	for k, vv := range qvals {
		r.scanTarget("ARGS_NAMES", k, &results)
		if err != nil {
			// TODO handle scan error
			return
		}

		for _, v := range vv {
			r.scanTarget("ARGS", v, &results)
			if err != nil {
				// TODO handle scan error
				return
			}
		}
	}

	return
}

func (r *reqScannerImpl) scanTarget(targetName string, content string, results *ScanResults) (err error) {
	// TODO look up in scanPatterns not only based on full target names, but also based on selectors with regexes
	for _, sg := range r.scanPatterns[targetName] {
		if len(sg.patterns) == 0 {
			continue
		}

		// TODO apply transformations here

		var matches []MultiRegexEngineMatch
		log.Printf("Scanning content \"%v\" with transformations %v", content, sg.transformations)
		matches, err = sg.rxEngine.Scan([]byte(content))
		if err != nil {
			return
		}

		for _, m := range matches {
			p := r.backRefs[m.ID]

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

// GetRxResultsFor returns any results for regex matches that were done during the request scanning.
func (r *ScanResults) GetRxResultsFor(ruleID int, ruleItemIdx int, target string) (m RxMatch, ok bool) {
	m, ok = r.rxMatches[rxMatchKey{ruleID: ruleID, ruleItemIdx: ruleItemIdx, target: target}]
	return
}

func transformationListEquals(a []Transformation, b []Transformation) bool {
	if len(a) != len(b) {
		return false
	}

	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
