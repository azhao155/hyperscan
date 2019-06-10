package secrule

import (
	pb "azwaf/proto"
	"net/url"
)

// ReqScanner scans requests for string matches and other properties that the rule engine will be needing to do rule evaluation.
type ReqScanner interface {
	Scan(req *pb.WafHttpRequest) (results ScanResults, err error)
}

// RxMatch represents a regex match found while scanning.
type RxMatch struct {
	EndPos int
}

// ScanResults is the collection of all results found while scanning.
type ScanResults struct {
	rxMatches map[rxMatchKey]RxMatch
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

// NewReqScanner creates a secrule.ReqScanner.
func NewReqScanner(rules []Rule, m MultiRegexEngineFactory) (r ReqScanner, err error) {
	scanPatterns := make(map[string][]*scanGroup)

	// Construct a inverted view of the rules that maps from targets to rules
	for curRuleIdx := range rules {
		curRule := &rules[curRuleIdx]
		for curRuleItemIdx := range curRule.Items {
			curRuleItem := &curRule.Items[curRuleItemIdx]
			for _, target := range curRuleItem.Targets {
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

				switch curRuleItem.Op {
				case Rx:
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
	for _, scanGroups := range scanPatterns {
		for _, scanGroup := range scanGroups {
			if len(scanGroup.patterns) == 0 {
				continue
			}

			patterns := []MultiRegexEnginePattern{}
			for _, p := range scanGroup.patterns {
				// This will allow us to navigate back to the actual rule when the multi scan engine finds a match.
				backRefs = append(backRefs, p)

				patterns = append(patterns, MultiRegexEnginePattern{backRefCurID, p.ruleItem.Val})

				backRefCurID++
			}

			scanGroup.rxEngine, err = m.NewMultiRegexEngine(patterns)
			if err != nil {
				// TODO error handling
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

func (r *reqScannerImpl) Scan(req *pb.WafHttpRequest) (results ScanResults, err error) {
	results.rxMatches = make(map[rxMatchKey]RxMatch)

	r.scanTarget("REQUEST_URI_RAW", req.Uri, &results)
	if err != nil {
		// TODO handle scan error
		return
	}

	var uriParsed *url.URL
	uriParsed, err = url.ParseRequestURI(req.Uri)
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
		// TODO apply transformations here

		var matches []MultiRegexEngineMatch
		matches, err = sg.rxEngine.Scan([]byte(content))
		if err != nil {
			return
		}

		for _, m := range matches {
			p := r.backRefs[m.ID]

			// Store the match for fast retrieval in the eval phase
			key := rxMatchKey{p.rule.ID, p.ruleItemIdx, targetName}
			if _, alreadyFound := results.rxMatches[key]; !alreadyFound {
				results.rxMatches[key] = RxMatch{EndPos: m.EndPos}
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
