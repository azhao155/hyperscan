package reqscanning

import (
	"azwaf/encoding"
	"azwaf/libinjection"
	sr "azwaf/secrule"
	"azwaf/secrule/ast"
	tr "azwaf/secrule/transformations"
	"azwaf/waf"
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// NewScanResults creates a ScanResults struct.
func NewScanResults() *sr.ScanResults {
	return &sr.ScanResults{
		Matches:      make(map[sr.MatchKey][]sr.Match),
		TargetsCount: make(map[ast.Target]int),
	}
}

// NewReqScannerFactory creates a ReqScannerFactory. The ReqScanners it will create will use multi-regex engines created by the given MultiRegexEngineFactory.
func NewReqScannerFactory(m waf.MultiRegexEngineFactory) sr.ReqScannerFactory {
	return &reqScannerFactoryImpl{m}
}

type reqScannerFactoryImpl struct {
	multiRegexEngineFactory waf.MultiRegexEngineFactory
}

type conditionRef struct {
	rule        *ast.Rule
	ruleItem    *ast.RuleItem
	ruleItemIdx int
	target      ast.Target
}

// Group of conditions that can be scanned together, because they are for the same target and with the same transformations.
type scanGroup struct {
	transformations       []ast.Transformation
	rxEngine              waf.MultiRegexEngine
	conditions            []conditionRef
	regexEngineRefsToCond []conditionRef
}

type reqScannerImpl struct {
	allScanGroups                             []*scanGroup
	scanGroupsForTarget                       map[ast.Target][]*scanGroup
	targetsSimple                             map[ast.Target]bool
	targetsRegexSelector                      map[ast.TargetName][]*targetsRegexSelectorWithSameTargetName
	exceptTargetsRegexSelectorsCompiled       map[string]*regexp.Regexp
	globalExceptTargets                       []ast.Target
	globalExceptTargetsRegexSelectorsCompiled map[string]*regexp.Regexp
}

type reqScannerEvaluationImpl struct {
	reqScanner   *reqScannerImpl
	scratchSpace *sr.ReqScannerScratchSpace
}

type targetsRegexSelectorWithSameTargetName struct {
	target                ast.Target
	regexSelectorCompiled *regexp.Regexp
}

var targetNamesFromExclusion = map[string][]ast.TargetName{
	"RequestArgNames":    {ast.TargetArgs, ast.TargetArgsGet, ast.TargetArgsPost},
	"RequestCookieNames": {ast.TargetRequestCookies},
	"RequestHeaderNames": {ast.TargetRequestHeaders},
}

// NewReqScanner creates a ReqScanner.
func (f *reqScannerFactoryImpl) NewReqScanner(statements []ast.Statement, exclusions []waf.Exclusion) (r sr.ReqScanner, err error) {
	var allScanGroups []*scanGroup
	scanGroupsForTarget := make(map[ast.Target][]*scanGroup)
	targetsSimple := make(map[ast.Target]bool)
	targetsRegexSelector := make(map[ast.TargetName][]*targetsRegexSelectorWithSameTargetName)
	exceptTargetsRegexSelectorsCompiled := make(map[string]*regexp.Regexp)
	globalExceptTargetsRegexSelectorsCompiled := make(map[string]*regexp.Regexp)

	// Construct a inverted view of the rules that maps from targets+selectors, to rule conditions
	for _, curStmt := range statements {
		curRule, ok := curStmt.(*ast.Rule)
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
					if tr.TransformationListEquals(sg.transformations, curRuleItem.Transformations) {
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

			// If there are any regex except-targets in this predicate, then pre-compile them.
			for _, exceptTarget := range curRuleItem.Predicate.ExceptTargets {
				if exceptTarget.IsRegexSelector {
					exceptTargetsRegexSelectorsCompiled[exceptTarget.Selector], err = regexp.Compile(exceptTarget.Selector)
					if err != nil {
						return
					}
				}
			}
		}
	}

	// Construct multi regex engine instances.
	for _, sg := range allScanGroups {
		// When the multi regex engine finds a match, it gives us a single ID. RegexEngineRefsToCond gets us from the ID to the actual rule.
		// RegexEngineRefsToCond is not the same as sg.conditions, because for @pmf there will be multiple patterns that needs to reference to the same condition, and the multi regex engine needs separate IDs for each pattern.
		regexEngineRefsToCond := []conditionRef{}
		refCurID := 0

		patterns := []waf.MultiRegexEnginePattern{}
		for _, p := range sg.conditions {
			op := p.ruleItem.Predicate.Op
			isHandledByRegexEngine := op == ast.Rx ||
				op == ast.Pm ||
				op == ast.Pmf ||
				op == ast.PmFromFile ||
				op == ast.BeginsWith ||
				op == ast.EndsWith ||
				op == ast.Contains ||
				op == ast.ContainsWord ||
				op == ast.Streq ||
				op == ast.Strmatch ||
				op == ast.Within

			if !isHandledByRegexEngine {
				continue
			}

			// The value can have macros that cannot be expanded at this time.
			if p.ruleItem.Predicate.Val.HasMacros() {
				continue
			}

			exprs := getRxExprs(p.ruleItem)
			for _, e := range exprs {
				// This will allow us to navigate back to the actual rule when the multi scan engine finds a match.
				regexEngineRefsToCond = append(regexEngineRefsToCond, p)
				patterns = append(patterns, waf.MultiRegexEnginePattern{refCurID, e})
				refCurID++
			}
		}

		if len(patterns) == 0 {
			// There were no conditions in this scan group that the regex engine can handle
			continue
		}

		sg.regexEngineRefsToCond = regexEngineRefsToCond
		sg.rxEngine, err = f.multiRegexEngineFactory.NewMultiRegexEngine(patterns)
		if err != nil {
			err = fmt.Errorf("failed to create multi-regex engine: %v", err)
			return
		}
	}

	globalExceptTargets := []ast.Target{}

	for _, e := range exclusions {
		for _, t := range targetNamesFromExclusion[e.MatchVariable()] {
			if e.SelectorMatchOperator() != "" && e.Selector() != "" {
				var expr string
				escapedVal := regexp.QuoteMeta(e.Selector())

				// possible optimization: use string operations directly instead of regexes.
				switch e.SelectorMatchOperator() {

				case "StartsWith":
					expr = "^" + escapedVal
				case "EndsWith":
					expr = escapedVal + "$"
				case "Contains":
					expr = escapedVal
				case "Equal":
					expr = "^" + escapedVal + "$"

				}

				globalExceptTargetsRegexSelectorsCompiled[e.Selector()], err = regexp.Compile(expr)
				if err != nil {
					return
				}

				globalExceptTargets = append(globalExceptTargets, ast.Target{Name: t, Selector: e.Selector(), IsRegexSelector: true})
			} else {
				// collections
				globalExceptTargets = append(globalExceptTargets, ast.Target{Name: t, Selector: ""})
			}
		}
	}

	r = &reqScannerImpl{
		allScanGroups:                             allScanGroups,
		scanGroupsForTarget:                       scanGroupsForTarget,
		targetsSimple:                             targetsSimple,
		targetsRegexSelector:                      targetsRegexSelector,
		exceptTargetsRegexSelectorsCompiled:       exceptTargetsRegexSelectorsCompiled,
		globalExceptTargets:                       globalExceptTargets,
		globalExceptTargetsRegexSelectorsCompiled: globalExceptTargetsRegexSelectorsCompiled,
	}

	return
}

func (r *reqScannerImpl) getTargets(targetName ast.TargetName, fieldName string) (targets []ast.Target) {
	// Also get targets that do not specify field names. Example: ARGS vs. ARGS:somefield.
	if fieldName != "" {
		targets = append(targets, r.getTargets(targetName, "")...)
	}

	fieldNameLower := strings.ToLower(fieldName)

	// Are we looking for this simple target?
	t := ast.Target{Name: targetName, Selector: fieldNameLower}
	if r.targetsSimple[t] {
		targets = append(targets, t)
	}

	// Are we looking for this simple count target?
	t = ast.Target{Name: targetName, Selector: fieldNameLower, IsCount: true}
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

func (r *reqScannerImpl) matchesExceptTargets(targetName ast.TargetName, fieldName string, exceptTargets []ast.Target) bool {
	for _, et := range exceptTargets {
		// Is this exceptTarget a simple target?
		if !et.IsRegexSelector {
			if targetName == et.Name && (et.Selector == "" || strings.EqualFold(fieldName, et.Selector)) {
				return true
			}
			continue
		}

		// Are we looking for a target with regex selector that this field name matches?
		if et.IsRegexSelector {
			if r.exceptTargetsRegexSelectorsCompiled[et.Selector].MatchString(fieldName) {
				return true
			}
		}
	}

	for _, get := range r.globalExceptTargets {
		// Is this exceptTarget a simple target?
		if !get.IsRegexSelector {
			if targetName == get.Name && (get.Selector == "" || strings.EqualFold(fieldName, get.Selector)) {
				return true
			}
			continue
		}

		// Are we looking for a target with regex selector that this field name matches?
		if get.IsRegexSelector {
			if r.globalExceptTargetsRegexSelectorsCompiled[get.Selector] != nil && r.globalExceptTargetsRegexSelectorsCompiled[get.Selector].MatchString(fieldName) {
				return true
			}
		}
	}

	return false
}

func (r *reqScannerImpl) NewReqScannerEvaluation(scratchSpace *sr.ReqScannerScratchSpace) sr.ReqScannerEvaluation {
	return &reqScannerEvaluationImpl{
		reqScanner:   r,
		scratchSpace: scratchSpace,
	}
}

// NewScratchSpace creates an instance of all the scratch spaces this ReqScanner will need.
func (r *reqScannerImpl) NewScratchSpace() (scratchSpace *sr.ReqScannerScratchSpace, err error) {
	s := make(sr.ReqScannerScratchSpace)

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

func (r *reqScannerEvaluationImpl) ScanHeaders(req waf.HTTPRequest, results *sr.ScanResults) (err error) {
	// We currently don't actually have the raw request line, because it's been parsed by Nginx and send in a struct to us.
	// TODO consider passing the raw request line from Nginx if available.
	protocol := req.Protocol()
	var reqLine bytes.Buffer
	reqLine.WriteString(req.Method())
	reqLine.WriteString(" ")
	reqLine.WriteString(req.URI())
	reqLine.WriteString(" ")
	reqLine.WriteString(protocol)
	err = r.scanField(ast.TargetRequestLine, "", reqLine.String(), results)
	if err != nil {
		return
	}

	results.RequestLine = reqLine.Bytes()
	results.RequestProtocol = []byte(protocol)

	err = r.scanField(ast.TargetRemoteAddr, "", req.RemoteAddr(), results)
	if err != nil {
		return
	}

	method := req.Method()
	results.RequestMethod = []byte(method)
	err = r.scanField(ast.TargetRequestMethod, "", method, results)
	if err != nil {
		return
	}

	err = r.scanURI(req.URI(), results)
	if err != nil {
		return
	}

	err = r.scanField(ast.TargetRequestProtocol, "", req.Protocol(), results)
	if err != nil {
		return
	}

	headers := req.Headers()
	for _, h := range headers {
		k := h.Key()
		v := h.Value()

		if strings.EqualFold(k, "host") {
			results.HostHeader = []byte(v)
		}

		if strings.EqualFold(k, "cookie") {
			r.scanCookies(v, results)
		}

		if strings.EqualFold(k, "content-type") {
			r.scanContentType(v, results)
		}

		err = r.scanField(ast.TargetRequestHeadersNames, "", k, results)
		if err != nil {
			return
		}

		err = r.scanField(ast.TargetRequestHeaders, k, v, results)
		if err != nil {
			return
		}

	}

	return
}

func (r *reqScannerEvaluationImpl) ScanBodyField(contentType waf.FieldContentType, fieldName string, data string, results *sr.ScanResults) (err error) {
	// TODO pass on certain content types that modsec doesnt handle?

	switch contentType {

	case waf.MultipartFormDataContent, waf.URLEncodedContent:
		err = r.scanField(ast.TargetArgsNames, "", fieldName, results)
		if err != nil {
			return
		}

		err = r.scanField(ast.TargetArgs, fieldName, data, results)
		if err != nil {
			return
		}

		err = r.scanField(ast.TargetArgsPost, fieldName, data, results)
		if err != nil {
			return
		}

	case waf.MultipartFormDataFileNames:
		err = r.scanField(ast.TargetFilesNames, "", fieldName, results)
		if err != nil {
			return
		}

		err = r.scanField(ast.TargetFiles, "", data, results)
		if err != nil {
			return
		}

	case waf.MultipartFormDataStrictnessWarning:
		switch fieldName {
		case waf.MultipartFormDataStrictnessWarningDataAfter:
			results.MultipartDataAfter = true
		case waf.MultipartFormDataStrictnessWarningDataBefore:
			results.MultipartDataBefore = true
		case waf.MultipartFormDataStrictnessWarningHeaderFolding:
			results.MultipartHeaderFolding = true
		case waf.MultipartFormDataStrictnessWarningInvalidHeaderFolding:
			results.MultipartInvalidHeaderFolding = true
		case waf.MultipartFormDataStrictnessWarningLfLine:
			results.MultipartLfLine = true
		case waf.MultipartFormDataStrictnessWarningUnmatchedBoundary:
			results.MultipartUnmatchedBoundary = true
		case waf.MultipartFormDataStrictnessWarningFileLimitExceeded:
			results.MultipartFileLimitExceeded = true
		case waf.MultipartFormDataStrictnessWarningIncomplete:
			results.MultipartIncomplete = true
		}

	case waf.JSONContent:
		err = r.scanField(ast.TargetArgs, "", data, results)
		if err != nil {
			return
		}

	case waf.XMLCharData:
		err = r.scanField(ast.TargetXML, "/*", data, results)
		if err != nil {
			return
		}

	case waf.XMLAttrVal:
		err = r.scanField(ast.TargetXML, "//@*", data, results)
		if err != nil {
			return
		}

	case waf.FullRawRequestBody:
		err = r.scanField(ast.TargetRequestBody, "", data, results)
		if err != nil {
			return
		}

	default:
		// TODO consider doing something sensible even for unknown request body types. ModSec doesn't though.

	}

	return
}

func (r *reqScannerEvaluationImpl) scanField(targetName ast.TargetName, fieldName string, content string, results *sr.ScanResults) (err error) {
	// TODO cache if a scan was already done for a given piece of content (consider Murmur hash: https://github.com/twmb/murmur3) and target name, and save time by skipping transforming and scanning it in that case. This could happen with repetitive JSON or XML bodies for example.
	// TODO this cache could even persist across requests, with some LRU purging approach. We could even hash and cache entire request bodies. Wow.

	var scanGroups []*scanGroup
	targets := r.reqScanner.getTargets(targetName, fieldName)
	for _, target := range targets {
		results.TargetsCount[target] = results.TargetsCount[target] + 1
		scanGroups = append(scanGroups, r.reqScanner.scanGroupsForTarget[target]...)
	}

	if len(scanGroups) == 0 {
		return
	}

	for _, sg := range scanGroups {
		contentTransformed := tr.ApplyTransformations(content, sg.transformations)

		// Handle all conditions in this scan group that the regex engine can handle
		if sg.rxEngine != nil {
			scratchSpace := (*r.scratchSpace)[&sg.rxEngine]

			var matches []waf.MultiRegexEngineMatch
			matches, err = sg.rxEngine.Scan([]byte(contentTransformed), scratchSpace)
			if err != nil {
				return
			}

			for _, m := range matches {
				p := sg.regexEngineRefsToCond[m.ID]

				if r.reqScanner.matchesExceptTargets(targetName, fieldName, p.ruleItem.Predicate.ExceptTargets) {
					continue
				}

				// Store the match for fast retrieval in the eval phase
				key := sr.MatchKey{p.rule.ID, p.ruleItemIdx, p.target}
				results.Matches[key] = append(results.Matches[key], sr.Match{
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
			key := sr.MatchKey{cr.rule.ID, cr.ruleItemIdx, cr.target}
			results.Matches[key] = append(results.Matches[key], sr.Match{
				CaptureGroups:      [][]byte{[]byte(content)},
				Data:               []byte(content),
				EntireFieldContent: []byte(content),
				TargetName:         targetName,
				FieldName:          []byte(fieldName),
			})
		}

		// Handle conditions that the regex engine could not handle
		for _, cr := range sg.conditions {
			if r.reqScanner.matchesExceptTargets(targetName, fieldName, cr.ruleItem.Predicate.ExceptTargets) {
				continue
			}

			switch cr.ruleItem.Predicate.Op {

			case ast.DetectXSS:
				if libinjection.IsXSS(contentTransformed) {
					storeEntireContentAsMatch(cr)
				}

			case ast.DetectSQLi:
				found, fingerprint := libinjection.IsSQLi(contentTransformed)
				if found {
					// TODO investigate if this "fingerprint" is actually meaningful to log. ModSec logs it, but I cannot make sense of the values.

					// Store the match for fast retrieval in the eval phase
					key := sr.MatchKey{cr.rule.ID, cr.ruleItemIdx, cr.target}
					results.Matches[key] = append(results.Matches[key], sr.Match{
						Data:               []byte([]byte(fingerprint)),
						CaptureGroups:      [][]byte{[]byte(fingerprint)},
						EntireFieldContent: []byte(content),
						TargetName:         targetName,
						FieldName:          []byte(fieldName),
					})
				}

			case ast.ValidateURLEncoding:
				if !encoding.IsValidURLEncoding(contentTransformed) {
					storeEntireContentAsMatch(cr)
				}

			case ast.ValidateByteRange:
				// It is safe to assume there is just one element in Val due to validation in the parser.
				vbrt := cr.ruleItem.Predicate.Val[0].(ast.ValidateByteRangeToken)

				// ValidateByteRangeToken.AllowedBytes is a fixed [256]bool, where the index represents a byte value.
				for i := 0; i < len(contentTransformed); i++ {
					if !vbrt.AllowedBytes[contentTransformed[i]] {
						storeEntireContentAsMatch(cr)
						break
					}
				}
			}
		}
	}

	return
}

func getRxExprs(ruleItem *ast.RuleItem) []string {
	s := ruleItem.Predicate.Val.String()
	quoted := regexp.QuoteMeta(s)
	switch ruleItem.Predicate.Op {
	case ast.Rx:
		return []string{s}
	case ast.Pm, ast.Pmf, ast.PmFromFile:
		var phrases []string
		for _, p := range ruleItem.PmPhrases {
			phrases = append(phrases, "(?i:"+regexp.QuoteMeta(p)+")")
		}
		return phrases
	case ast.BeginsWith:
		return []string{"^" + quoted}
	case ast.EndsWith:
		return []string{quoted + "$"}
	case ast.Contains, ast.Strmatch:
		return []string{quoted}
	case ast.ContainsWord:
		return []string{`\b` + quoted + `\b`}
	case ast.Streq:
		return []string{"^" + quoted + "$"}
	case ast.Within:
		var words []string
		var parameterStrings = strings.Split(s, " ")
		for _, p := range parameterStrings {
			words = append(words, "^"+regexp.QuoteMeta(p)+"$")
		}
		return words
	}

	return nil
}

func (r *reqScannerEvaluationImpl) scanURI(URI string, results *sr.ScanResults) (err error) {
	err = r.scanField(ast.TargetRequestURI, "", URI, results)
	if err != nil {
		return
	}

	err = r.scanField(ast.TargetRequestURIRaw, "", URI, results)
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

	err = r.scanField(ast.TargetRequestFilename, "", reqFilename, results)
	if err != nil {
		return
	}

	reqBasename := reqFilename
	n = strings.LastIndexAny(reqBasename, `/\`)
	if n != -1 {
		reqBasename = reqFilename[n+1:]
	}

	err = r.scanField(ast.TargetRequestBasename, "", reqBasename, results)
	if err != nil {
		return
	}

	err = r.scanField(ast.TargetQueryString, "", queryString, results)
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
			err = r.scanField(ast.TargetArgsNames, "", qval.key, results)
			if err != nil {
				return
			}

			err = r.scanField(ast.TargetArgsGetNames, "", qval.key, results)
			if err != nil {
				return
			}

			scannedKey[qval.key] = true
		}

		err = r.scanField(ast.TargetArgs, qval.key, qval.val, results)
		if err != nil {
			return
		}

		err = r.scanField(ast.TargetArgsGet, qval.key, qval.val, results)
		if err != nil {
			return
		}
	}

	return
}

func (r *reqScannerEvaluationImpl) scanCookies(c string, results *sr.ScanResults) (err error) {
	cc := strings.Split(c, ";")

	for _, s := range cc {
		s = strings.Trim(s, " ")

		var k, v string
		k = s
		eqPos := strings.IndexByte(s, '=')
		if eqPos != -1 {
			k = s[:eqPos]
			v = s[eqPos+1:]
		}

		err = r.scanField(ast.TargetRequestCookiesNames, "", k, results)
		if err != nil {
			return
		}

		err = r.scanField(ast.TargetRequestCookies, k, v, results)
		if err != nil {
			return
		}
	}

	return
}

func (r *reqScannerEvaluationImpl) scanContentType(v string, results *sr.ScanResults) {
	valLowerTrimmed := strings.TrimLeft(strings.ToLower(v), " ")
	if strings.HasPrefix(valLowerTrimmed, "multipart/form-data") {
		if !strings.ContainsAny(valLowerTrimmed, ";") {
			results.MultipartMissingSemicolon = true
		} else {
			ss := strings.Split(valLowerTrimmed, ";")
			for _, s := range ss {
				s = strings.TrimLeft(s, " ")
				if strings.HasPrefix(s, "boundary=") {
					s = strings.TrimPrefix(s, "boundary=")
					if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
						results.MultipartBoundaryQuoted = true
					} else if strings.ContainsAny(s, "'\"") {
						results.MultipartInvalidQuoting = true
					}

					for _, c := range s {
						if unicode.IsSpace(c) {
							results.MultipartBoundaryWhitespace = true
						}
					}
				}
			}
		}
	}
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
