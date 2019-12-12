package secrule

import (
	"azwaf/encoding"
	"azwaf/libinjection"
	"azwaf/waf"
	"bytes"
	"fmt"
	"net/http"
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
	ScanHeaders(req waf.HTTPRequest, results *ScanResults) (err error)
	ScanBodyField(contentType waf.FieldContentType, fieldName string, data string, results *ScanResults) error
}

// Match represents when a match was found during the request scanning phase.
type Match struct {
	Data               []byte
	CaptureGroups      [][]byte
	EntireFieldContent []byte
	TargetName         TargetName
	FieldName          []byte
}

// ScanResults is the collection of all results found while scanning.
type ScanResults struct {
	matches         map[matchKey][]Match
	targetsCount    map[Target]int
	requestLine     []byte
	requestMethod   []byte
	requestProtocol []byte
	hostHeader      []byte
}

// NewScanResults creates a ScanResults struct.
func NewScanResults() *ScanResults {
	return &ScanResults{
		matches:      make(map[matchKey][]Match),
		targetsCount: make(map[Target]int),
	}
}

// ReqScannerFactory creates ReqScanners. This makes mocking possible when testing.
type ReqScannerFactory interface {
	NewReqScanner(statements []Statement) (r ReqScanner, err error)
}

// NewReqScannerFactory creates a ReqScannerFactory. The ReqScanners it will create will use multi-regex engines created by the given MultiRegexEngineFactory.
func NewReqScannerFactory(m waf.MultiRegexEngineFactory) ReqScannerFactory {
	return &reqScannerFactoryImpl{m}
}

// ReqScannerScratchSpace is a collection of all the scratch spaces a ReqScanner will need. These can be reused for different requests, but cannot be shared concurrently.
type ReqScannerScratchSpace map[*waf.MultiRegexEngine]waf.MultiRegexEngineScratchSpace

type reqScannerFactoryImpl struct {
	multiRegexEngineFactory waf.MultiRegexEngineFactory
}

type matchKey struct {
	ruleID      int
	ruleItemIdx int
	target      Target
}

type conditionRef struct {
	rule        *Rule
	ruleItem    *RuleItem
	ruleItemIdx int
	target      Target
}

// Group of conditions that can be scanned together, because they are for the same target and with the same transformations.
type scanGroup struct {
	transformations []Transformation
	rxEngine        waf.MultiRegexEngine
	conditions      []conditionRef
	backRefs        []conditionRef
}

type reqScannerImpl struct {
	allScanGroups        []*scanGroup
	scanGroupsForTarget  map[Target][]*scanGroup
	targetsSimple        map[Target]bool
	targetsRegexSelector map[TargetName][]*targetsRegexSelectorWithSameTargetName
}

type reqScannerEvaluationImpl struct {
	reqScanner   *reqScannerImpl
	scratchSpace *ReqScannerScratchSpace
}

type targetsRegexSelectorWithSameTargetName struct {
	target                Target
	regexSelectorCompiled *regexp.Regexp
}

// NewReqScanner creates a ReqScanner.
func (f *reqScannerFactoryImpl) NewReqScanner(statements []Statement) (r ReqScanner, err error) {
	var allScanGroups []*scanGroup
	scanGroupsForTarget := make(map[Target][]*scanGroup)
	targetsSimple := make(map[Target]bool)
	targetsRegexSelector := make(map[TargetName][]*targetsRegexSelectorWithSameTargetName)

	// Construct a inverted view of the rules that maps from targets+selectors, to rule conditions
	for _, curStmt := range statements {
		curRule, ok := curStmt.(*Rule)
		if !ok {
			// This statement was not a rule
			continue
		}

		for curRuleItemIdx := range curRule.Items {
			curRuleItem := &curRule.Items[curRuleItemIdx]
			for _, target := range curRuleItem.Predicate.Targets {
				if target.IsRegexSelector {
					// Add this target to targetsRegexSelector if not already present
					aa := targetsRegexSelector[target.Name]
					found := false
					for _, a := range aa {
						if a.target == target {
							found = true
							break
						}
					}
					if !found {
						var rx *regexp.Regexp
						rx, err = regexp.Compile(target.Selector)
						if err != nil {
							return
						}
						aa = append(aa, &targetsRegexSelectorWithSameTargetName{
							target:                target,
							regexSelectorCompiled: rx,
						})
						targetsRegexSelector[target.Name] = aa
					}
				} else {
					targetsSimple[target] = true
				}

				// This target+selector can have multiple different transformations. Find the right one or create one.
				var curScanGroup *scanGroup
				for _, sg := range scanGroupsForTarget[target] {
					if transformationListEquals(sg.transformations, curRuleItem.Transformations) {
						curScanGroup = sg
						break
					}
				}
				if curScanGroup == nil {
					// This is the first time we see a RuleItem for this combination of target+selector+transformations, so we'll create a scanGroup object for it.
					curScanGroup = &scanGroup{transformations: curRuleItem.Transformations}
					scanGroupsForTarget[target] = append(scanGroupsForTarget[target], curScanGroup)
					allScanGroups = append(allScanGroups, curScanGroup)
				}

				// Mark that this condition is subscribed to this scanGroup
				p := conditionRef{curRule, curRuleItem, curRuleItemIdx, target}
				curScanGroup.conditions = append(curScanGroup.conditions, p)
			}
		}
	}

	// Construct multi regex engine instances.
	for _, sg := range allScanGroups {
		// When the multi regex engine finds a match, it gives us a single ID. BackRefs gets us from the ID to the actual rule.
		// BackRefs is not the same as sg.conditions, because for @pmf there will be multiple patterns that needs to reference to the same condition, and the multi regex engine needs separate IDs for each pattern.
		backRefs := []conditionRef{}
		backRefCurID := 0

		patterns := []waf.MultiRegexEnginePattern{}
		for _, p := range sg.conditions {
			switch p.ruleItem.Predicate.Op {
			case Rx, Pm, Pmf, PmFromFile, BeginsWith, EndsWith, Contains, ContainsWord, Streq, Strmatch, Within:
				// The value can have macros that cannot be expanded at this time.
				if p.ruleItem.Predicate.Val.hasMacros() {
					continue
				}

				exprs := getRxExprs(p.ruleItem)
				for _, e := range exprs {
					// This will allow us to navigate back to the actual rule when the multi scan engine finds a match.
					backRefs = append(backRefs, p)
					patterns = append(patterns, waf.MultiRegexEnginePattern{backRefCurID, e})
					backRefCurID++
				}
			}
		}

		if len(patterns) == 0 {
			// There were no conditions in this scan group that the regex engine can handle
			continue
		}

		sg.backRefs = backRefs
		sg.rxEngine, err = f.multiRegexEngineFactory.NewMultiRegexEngine(patterns)
		if err != nil {
			err = fmt.Errorf("failed to create multi-regex engine: %v", err)
			return
		}
	}

	r = &reqScannerImpl{
		allScanGroups:        allScanGroups,
		scanGroupsForTarget:  scanGroupsForTarget,
		targetsSimple:        targetsSimple,
		targetsRegexSelector: targetsRegexSelector,
	}

	return
}

func (r *reqScannerImpl) getTargets(targetName TargetName, fieldName string) (targets []Target) {
	// Also get targets that do not specify field names. Example: ARGS vs. ARGS:somefield.
	if fieldName != "" {
		targets = append(targets, r.getTargets(targetName, "")...)
	}

	fieldNameLower := strings.ToLower(fieldName)

	// Are we looking for this simple target?
	t := Target{Name: targetName, Selector: fieldNameLower}
	if r.targetsSimple[t] {
		targets = append(targets, t)
	}

	// Are we looking for this simple count target?
	t = Target{Name: targetName, Selector: fieldNameLower, IsCount: true}
	if r.targetsSimple[t] {
		targets = append(targets, t)
	}

	// Are we looking for a target with regex selector that this field name matches?
	for _, trs := range r.targetsRegexSelector[targetName] {
		if trs.regexSelectorCompiled.MatchString(fieldName) {
			targets = append(targets, trs.target)
		}
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

	for _, sg := range r.allScanGroups {
		if sg.rxEngine == nil {
			// Happens with scan groups with no regex patterns
			continue
		}

		s[&sg.rxEngine], err = sg.rxEngine.CreateScratchSpace()
		if err != nil {
			return
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

func (r *reqScannerEvaluationImpl) ScanHeaders(req waf.HTTPRequest, results *ScanResults) (err error) {
	// We currently don't actually have the raw request line, because it's been parsed by Nginx and send in a struct to us.
	// TODO consider passing the raw request line from Nginx if available.
	protocol := req.Protocol()
	var reqLine bytes.Buffer
	reqLine.WriteString(req.Method())
	reqLine.WriteString(" ")
	reqLine.WriteString(req.URI())
	reqLine.WriteString(" ")
	reqLine.WriteString(protocol)
	err = r.scanField(TargetRequestLine, "", reqLine.String(), results)
	if err != nil {
		return
	}

	results.requestLine = reqLine.Bytes()
	results.requestProtocol = []byte(protocol)

	err = r.scanField(TargetRemoteAddr, "", req.RemoteAddr(), results)
	if err != nil {
		return
	}

	method := req.Method()
	results.requestMethod = []byte(method)
	err = r.scanField(TargetRequestMethod, "", method, results)
	if err != nil {
		return
	}

	err = r.scanURI(req.URI(), results)
	if err != nil {
		return
	}

	err = r.scanField(TargetRequestProtocol, "", req.Protocol(), results)
	if err != nil {
		return
	}

	headers := req.Headers()
	for _, h := range headers {
		k := h.Key()
		v := h.Value()

		if strings.EqualFold(k, "host") {
			results.hostHeader = []byte(v)
		}

		if strings.EqualFold(k, "cookie") {
			r.scanCookies(v, results)
		}

		err = r.scanField(TargetRequestHeadersNames, "", k, results)
		if err != nil {
			return
		}

		// TODO selector probably should not be case sensitive
		err = r.scanField(TargetRequestHeaders, k, v, results)
		if err != nil {
			return
		}

	}

	return
}

func (r *reqScannerEvaluationImpl) ScanBodyField(contentType waf.FieldContentType, fieldName string, data string, results *ScanResults) (err error) {
	// TODO pass on certain content types that modsec doesnt handle?

	switch contentType {

	case waf.MultipartFormDataContent, waf.URLEncodedContent:
		err = r.scanField(TargetArgsNames, "", fieldName, results)
		if err != nil {
			return
		}

		err = r.scanField(TargetArgs, fieldName, data, results)
		if err != nil {
			return
		}

		err = r.scanField(TargetArgsPost, fieldName, data, results)
		if err != nil {
			return
		}

	case waf.MultipartFormDataFileNames:
		err = r.scanField(TargetFilesNames, "", fieldName, results)
		if err != nil {
			return
		}

		err = r.scanField(TargetFiles, "", data, results)
		if err != nil {
			return
		}

	case waf.JSONContent:
		err = r.scanField(TargetArgs, "", data, results)
		if err != nil {
			return
		}

	case waf.XMLContent:
		err = r.scanField(TargetXML, "/*", data, results)
		if err != nil {
			return
		}

	case waf.FullRawRequestBody:
		err = r.scanField(TargetRequestBody, "", data, results)
		if err != nil {
			return
		}

	default:
		// TODO consider doing something sensible even for unknown request body types. ModSec doesn't though.

	}

	return
}

// GetResultsFor returns any results for matches that were done during the request scanning.
func (r *ScanResults) GetResultsFor(ruleID int, ruleItemIdx int, target Target) (mm []Match, ok bool) {
	// TODO rename this function to just GetResultsFor
	mm, ok = r.matches[matchKey{ruleID: ruleID, ruleItemIdx: ruleItemIdx, target: target}]
	return
}

func (r *reqScannerEvaluationImpl) scanField(targetName TargetName, fieldName string, content string, results *ScanResults) (err error) {
	// TODO cache if a scan was already done for a given piece of content (consider Murmur hash: https://github.com/twmb/murmur3) and target name, and save time by skipping transforming and scanning it in that case. This could happen with repetitive JSON or XML bodies for example.
	// TODO this cache could even persist across requests, with some LRU purging approach. We could even hash and cache entire request bodies. Wow.

	var scanGroups []*scanGroup
	targets := r.reqScanner.getTargets(targetName, fieldName)
	for _, target := range targets {
		results.targetsCount[target] = results.targetsCount[target] + 1
		scanGroups = append(scanGroups, r.reqScanner.scanGroupsForTarget[target]...)
	}

	if len(scanGroups) == 0 {
		return
	}

	for _, sg := range scanGroups {
		contentTransformed := applyTransformations(content, sg.transformations)

		// Handle all conditions in this scan group that the regex engine can handle
		if sg.rxEngine != nil {
			scratchSpace := (*r.scratchSpace)[&sg.rxEngine]

			var matches []waf.MultiRegexEngineMatch
			matches, err = sg.rxEngine.Scan([]byte(contentTransformed), scratchSpace)
			if err != nil {
				return
			}

			for _, m := range matches {
				p := sg.backRefs[m.ID]

				// Store the match for fast retrieval in the eval phase
				key := matchKey{p.rule.ID, p.ruleItemIdx, p.target}
				results.matches[key] = append(results.matches[key], Match{
					Data:               m.Data,
					CaptureGroups:      m.CaptureGroups,
					EntireFieldContent: []byte(content),
					TargetName:         targetName,
					FieldName:          []byte(fieldName),
				})
			}
		}

		storeEntireContentAsMatch := func(cr conditionRef) {
			// Store entire content as match for fast retrieval in the eval phase
			key := matchKey{cr.rule.ID, cr.ruleItemIdx, cr.target}
			results.matches[key] = append(results.matches[key], Match{
				CaptureGroups:      [][]byte{[]byte(content)},
				Data:               []byte(content),
				EntireFieldContent: []byte(content),
				TargetName:         targetName,
				FieldName:          []byte(fieldName),
			})
		}

		// Handle conditions that the regex engine could not handle
		for _, cr := range sg.conditions {
			switch cr.ruleItem.Predicate.Op {

			case DetectXSS:
				if libinjection.IsXSS(contentTransformed) {
					storeEntireContentAsMatch(cr)
				}

			case DetectSQLi:
				found, fingerprint := libinjection.IsSQLi(contentTransformed)
				if found {
					// TODO investigate if this "fingerprint" is actually meaningful to log. ModSec logs it, but I cannot make sense of the values.

					// Store the match for fast retrieval in the eval phase
					key := matchKey{cr.rule.ID, cr.ruleItemIdx, cr.target}
					results.matches[key] = append(results.matches[key], Match{
						Data:               []byte([]byte(fingerprint)),
						CaptureGroups:      [][]byte{[]byte(fingerprint)},
						EntireFieldContent: []byte(content),
						TargetName:         targetName,
						FieldName:          []byte(fieldName),
					})
				}

			case ValidateURLEncoding:
				if !encoding.IsValidURLEncoding(contentTransformed) {
					storeEntireContentAsMatch(cr)
				}

			case ValidateByteRange:
				// It is safe to assume there is just one element in Val due to validation in the parser.
				vbrt := cr.ruleItem.Predicate.Val[0].(ValidateByteRangeToken)

				// ValidateByteRangeToken.allowedBytes is a fixed [256]bool, where the index represents a byte value.
				for i := 0; i < len(contentTransformed); i++ {
					if !vbrt.allowedBytes[contentTransformed[i]] {
						storeEntireContentAsMatch(cr)
						break
					}
				}
			}
		}
	}

	return
}

func getRxExprs(ruleItem *RuleItem) []string {
	s := ruleItem.Predicate.Val.string()
	quoted := regexp.QuoteMeta(s)
	switch ruleItem.Predicate.Op {
	case Rx:
		return []string{s}
	case Pm, Pmf, PmFromFile:
		var phrases []string
		for _, p := range ruleItem.PmPhrases {
			phrases = append(phrases, "(?i:"+regexp.QuoteMeta(p)+")")
		}
		return phrases
	case BeginsWith:
		return []string{"^" + quoted}
	case EndsWith:
		return []string{quoted + "$"}
	case Contains, Strmatch:
		return []string{quoted}
	case ContainsWord:
		return []string{`\b` + quoted + `\b`}
	case Streq:
		return []string{"^" + quoted + "$"}
	case Within:
		var words []string
		var parameterStrings = strings.Split(s, " ")
		for _, p := range parameterStrings {
			words = append(words, "^"+regexp.QuoteMeta(p)+"$")
		}
		return words
	}

	return nil
}

func (r *reqScannerEvaluationImpl) scanURI(URI string, results *ScanResults) (err error) {
	err = r.scanField(TargetRequestURI, "", URI, results)
	if err != nil {
		return
	}

	err = r.scanField(TargetRequestURIRaw, "", URI, results)
	if err != nil {
		return
	}

	// The "filename" is the part before the question mark.
	reqFilename := URI
	var queryString string
	n := strings.IndexByte(URI, '?')
	if n != -1 {
		reqFilename = URI[:n]
		queryString = URI[n+1:]
	}

	reqFilename = encoding.WeakURLUnescape(reqFilename)

	err = r.scanField(TargetRequestFilename, "", reqFilename, results)
	if err != nil {
		return
	}

	reqBasename := reqFilename
	n = strings.LastIndexAny(reqBasename, `/\`)
	if n != -1 {
		reqBasename = reqFilename[n+1:]
	}

	err = r.scanField(TargetRequestBasename, "", reqBasename, results)
	if err != nil {
		return
	}

	err = r.scanField(TargetQueryString, "", queryString, results)
	if err != nil {
		return
	}

	var qvals []qvalpair
	qvals, err = parseQuery(queryString)
	if err != nil {
		return
	}

	scannedKey := make(map[string]bool)
	for _, qval := range qvals {
		if !scannedKey[qval.key] {
			err = r.scanField(TargetArgsNames, "", qval.key, results)
			if err != nil {
				return
			}

			err = r.scanField(TargetArgsGetNames, "", qval.key, results)
			if err != nil {
				return
			}

			scannedKey[qval.key] = true
		}

		err = r.scanField(TargetArgs, qval.key, qval.val, results)
		if err != nil {
			return
		}

		err = r.scanField(TargetArgsGet, qval.key, qval.val, results)
		if err != nil {
			return
		}
	}

	return
}

func (r *reqScannerEvaluationImpl) scanCookies(c string, results *ScanResults) (err error) {
	// Use Go's http.Request to parse the cookies.
	goReq := &http.Request{Header: http.Header{"Cookie": []string{c}}}
	cookies := goReq.Cookies()
	for _, cookie := range cookies {

		err = r.scanField(TargetRequestCookiesNames, "", cookie.Name, results)
		if err != nil {
			return
		}

		err = r.scanField(TargetRequestCookies, cookie.Name, cookie.Value, results)
		if err != nil {
			return
		}
	}

	return
}

type qvalpair struct {
	key string
	val string
}

// Similar to url.ParseQuery, but does not consider semicolon as a delimiter. ModSecurity also does not consider semicolon a delimiter.
func parseQuery(query string) (values []qvalpair, err error) {
	if query == "" {
		return
	}

	for _, arg := range strings.Split(query, "&") {
		var pair qvalpair

		eqPos := strings.IndexByte(arg, '=')
		if eqPos != -1 {
			pair.key = encoding.WeakURLUnescape(arg[:eqPos])

			if eqPos+1 < len(arg) {
				pair.val = encoding.WeakURLUnescape(arg[eqPos+1:])
			}
		} else {
			pair.key = encoding.WeakURLUnescape(arg)
		}

		values = append(values, pair)
	}

	return
}
