package customrule

import (
	"azwaf/encoding"
	"azwaf/ipaddresses"
	"azwaf/waf"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
)

type customRuleEngineFactoryImpl struct {
	multiRegexEngineFactory waf.MultiRegexEngineFactory
	resultsLogger           waf.CustomRuleResultsLogger
	geoDB                   waf.GeoDB
}

// NewEngineFactory creates a custom rule engine factory
func NewEngineFactory(multiRegexEngineFactory waf.MultiRegexEngineFactory, geoDB waf.GeoDB) waf.CustomRuleEngineFactory {
	return &customRuleEngineFactoryImpl{
		multiRegexEngineFactory: multiRegexEngineFactory,
		geoDB:                   geoDB,
	}
}

func (f *customRuleEngineFactoryImpl) NewEngine(customRuleConfig waf.CustomRuleConfig) (customRuleEngine waf.CustomRuleEngine, err error) {
	engine := &customRuleEngineImpl{
		rules:           customRuleConfig.CustomRules(),
		geoDB:           f.geoDB,
		conditionGroups: make(map[matchVariable]*conditionsWithSameMatchVar),
	}

	// Sort custom rules by priority
	sort.Slice(engine.rules, func(i, j int) bool {
		return engine.rules[i].Priority() < engine.rules[j].Priority()
	})

	// Construct an inverted view of the rules that maps from MatchVariables to MatchConditions
	for ruleIdx, rule := range engine.rules {
		if rule.RuleType() != "MatchRule" {
			// TODO figure out what the meaning of other rule types are
			continue
		}

		for mcIdx, mc := range rule.MatchConditions() {

			for _, m := range mc.MatchVariables() {
				mv := matchVariable{m.VariableName(), m.Selector()}

				// Use existing struct for this MatchVariable or create new one if not yet created
				var cwsmv *conditionsWithSameMatchVar
				var ok bool
				if cwsmv, ok = engine.conditionGroups[mv]; !ok {
					cwsmv = &conditionsWithSameMatchVar{}
					engine.conditionGroups[mv] = cwsmv
				}

				// Use existing struct for this transformation-pipeline or create new one if not yet created
				var cwsmvt *conditionsWithSameMatchVarAndTransformations
				for _, existingCwsmvt := range cwsmv.sameTransformations {
					if stringSliceEquals(existingCwsmvt.transformations, mc.Transforms()) {
						cwsmvt = existingCwsmvt
					}
				}
				if cwsmvt == nil {
					cwsmvt = &conditionsWithSameMatchVarAndTransformations{
						transformations: mc.Transforms(),
					}
					cwsmv.sameTransformations = append(cwsmv.sameTransformations, cwsmvt)
				}

				cwsmvt.matchConditionPaths = append(cwsmvt.matchConditionPaths, matchConditionPath{ruleIdx, mcIdx})
			}
		}
	}

	// Construct multi regex engine instances when relevant
	for cgIdx, cg := range engine.conditionGroups {
		for stIdx, st := range cg.sameTransformations {
			groupRegexPatterns := []waf.MultiRegexEnginePattern{}

			// BackRefs is not the same as st.matchConditionPaths, because there can be multiple values that needs to reference to the same condition, and the multi regex engine needs separate IDs for each pattern.
			backRefs := []matchConditionPath{}
			backRefCurID := 0

			for _, path := range st.matchConditionPaths {
				mc := engine.rules[path.ruleIdx].MatchConditions()[path.mcIdx]
				for _, val := range mc.MatchValues() {
					escapedVal := regexp.QuoteMeta(val)

					//TODO: need to be aware of the HyperScan regex limit, consider splitting into multiple rules
					var expr string
					switch mc.Operator() {
					case "Regex":
						expr = val
					case "BeginsWith":
						expr = "^" + escapedVal
					case "EndsWith":
						expr = escapedVal + "$"
					case "Contains":
						expr = escapedVal
					case "Equals":
						expr = "^" + escapedVal + "$"
					}

					if expr != "" {
						groupRegexPatterns = append(groupRegexPatterns, waf.MultiRegexEnginePattern{ID: backRefCurID, Expr: expr})
						backRefs = append(backRefs, path)
						backRefCurID++
					}
				}
			}

			if len(groupRegexPatterns) == 0 {
				continue
			}

			// All these conditions are for the same MatchVariable and with same transformations, so we can therefore put them in the same MultiRegexEngine
			var m waf.MultiRegexEngine
			m, err = f.multiRegexEngineFactory.NewMultiRegexEngine(groupRegexPatterns)
			if err != nil {
				return
			}
			engine.conditionGroups[cgIdx].sameTransformations[stIdx].multiRegexEngine = m
			engine.conditionGroups[cgIdx].sameTransformations[stIdx].backRefs = backRefs
		}
	}

	// Buffered channel used for reuse of scratch spaces between requests, while not letting concurrent requests share the same scratch space.
	engine.scratchSpaceNext = make(chan *scratchSpaces, 100000)
	s, err := engine.newScratchSpace()
	if err != nil {
		panic(err)
	}
	engine.scratchSpaceNext <- s

	customRuleEngine = engine
	return
}

type customRuleEngineImpl struct {
	rules            []waf.CustomRule
	geoDB            waf.GeoDB
	conditionGroups  map[matchVariable]*conditionsWithSameMatchVar
	scratchSpaceNext chan *scratchSpaces
}

type matchVariable struct {
	variableName string
	selector     string
}

// Example: two separate rules both have conditions that target the QueryString match variable
type conditionsWithSameMatchVar struct {
	sameTransformations []*conditionsWithSameMatchVarAndTransformations
}

// Example: two separate rules both have conditions that target the QueryString match variable and also both want the transformations ["UrlDecode","Lowercase"]
type conditionsWithSameMatchVarAndTransformations struct {
	transformations     []string
	matchConditionPaths []matchConditionPath
	backRefs            []matchConditionPath
	multiRegexEngine    waf.MultiRegexEngine
}

type matchConditionPath struct {
	ruleIdx int
	mcIdx   int
}

type scratchSpaces map[*waf.MultiRegexEngine]waf.MultiRegexEngineScratchSpace

type customRuleEvaluationImpl struct {
	engine                *customRuleEngineImpl
	resultsLogger         waf.CustomRuleResultsLogger
	req                   waf.HTTPRequest
	results               *scanResults
	scratchSpacesInstance *scratchSpaces
}

func (c *customRuleEngineImpl) NewEvaluation(logger zerolog.Logger, resultsLogger waf.CustomRuleResultsLogger, req waf.HTTPRequest) waf.CustomRuleEvaluation {
	// Reuse a scratch space, or create a new one if there are none available
	var scratchSpacesInstance *scratchSpaces
	if len(c.scratchSpaceNext) > 0 {
		scratchSpacesInstance = <-c.scratchSpaceNext
	} else {
		var err error
		scratchSpacesInstance, err = c.newScratchSpace()
		if err != nil {
			panic(err)
		}
	}

	return &customRuleEvaluationImpl{
		engine:                c,
		resultsLogger:         resultsLogger,
		req:                   req,
		results:               &scanResults{matches: make(map[matchConditionPath]match)},
		scratchSpacesInstance: scratchSpacesInstance,
	}
}

func (c *customRuleEngineImpl) newScratchSpace() (scratchSpacesInstance *scratchSpaces, err error) {
	s := make(scratchSpaces)

	for _, cg := range c.conditionGroups {
		for _, st := range cg.sameTransformations {
			if st.multiRegexEngine == nil {
				continue
			}

			s[&st.multiRegexEngine], err = st.multiRegexEngine.CreateScratchSpace()
			if err != nil {
				return
			}
		}
	}

	scratchSpacesInstance = &s
	return
}

func (e *customRuleEvaluationImpl) ScanHeaders() (err error) {
	err = e.scanTarget(matchVariable{variableName: "RemoteAddr"}, e.req.RemoteAddr(), e.results)
	if err != nil {
		return
	}

	err = e.scanTarget(matchVariable{variableName: "RequestMethod"}, e.req.Method(), e.results)
	if err != nil {
		return
	}

	var queryString string
	n := strings.IndexByte(e.req.URI(), '?')
	if n != -1 {
		queryString = e.req.URI()[n+1:]
	}

	err = e.scanTarget(matchVariable{variableName: "QueryString"}, queryString, e.results)
	if err != nil {
		return
	}

	err = e.scanTarget(matchVariable{variableName: "RequestUri"}, e.req.URI(), e.results)
	if err != nil {
		return
	}

	for _, h := range e.req.Headers() {
		k := h.Key()
		v := h.Value()

		if strings.EqualFold(k, "cookie") {
			e.scanCookies(v, e.results)
		}

		err = e.scanTarget(matchVariable{variableName: "RequestHeaders"}, v, e.results)
		if err != nil {
			return
		}

		err = e.scanTarget(matchVariable{variableName: "RequestHeaders", selector: k}, v, e.results)
		if err != nil {
			return
		}
	}

	return
}

func (e *customRuleEvaluationImpl) ScanBodyField(contentType waf.ContentType, fieldName string, data string) (err error) {
	if contentType != waf.URLEncodedContent {
		// TODO Consider removing this silly constraint we have because we have it in our ModSec version.
		return
	}

	err = e.scanTarget(matchVariable{variableName: "PostArgs"}, data, e.results)
	if err != nil {
		return
	}

	err = e.scanTarget(matchVariable{variableName: "PostArgs", selector: fieldName}, data, e.results)
	if err != nil {
		return
	}

	err = e.scanTarget(matchVariable{variableName: "RequestBody"}, data, e.results)
	if err != nil {
		return
	}

	err = e.scanTarget(matchVariable{variableName: "RequestBody", selector: fieldName}, data, e.results)
	if err != nil {
		return
	}

	return
}

func (e *customRuleEvaluationImpl) EvalRules() waf.Decision {
	rules := e.engine.rules

	for ruleIdx, rule := range rules {
		allConditionsSatisfied := true
		for mcIdx := range rule.MatchConditions() {
			mcp := matchConditionPath{ruleIdx, mcIdx}
			if _, ok := e.results.matches[mcp]; !ok {
				allConditionsSatisfied = false
				break
			}
		}

		if !allConditionsSatisfied {
			continue
		}

		// Prepare struct for logging that describes the data that triggered the conditions
		rlcrmc := make([]waf.ResultsLoggerCustomRulesMatchedConditions, len(rule.MatchConditions()))
		for mcIdx := range rule.MatchConditions() {
			mcp := matchConditionPath{ruleIdx, mcIdx}
			rlcrmc[mcIdx].ConditionIndex = mcIdx
			rlcrmc[mcIdx].VariableName = e.results.matches[mcp].VariableName
			rlcrmc[mcIdx].FieldName = e.results.matches[mcp].FieldName
			rlcrmc[mcIdx].MatchedValue = string(e.results.matches[mcp].Data)
		}

		e.resultsLogger.CustomRuleTriggered(rule.Name(), rule.Action(), rlcrmc)

		switch rule.Action() {
		case "Allow":
			return waf.Allow
		case "Block":
			return waf.Block
		case "Log":
			// Already logged above. This action is kind of like "Pass" but within the custom rules engine.
		}
	}

	return waf.Pass
}

// Release resources.
func (e *customRuleEvaluationImpl) Close() {
	e.engine.scratchSpaceNext <- e.scratchSpacesInstance
}

type match struct {
	VariableName string
	FieldName    string
	StartPos     int
	EndPos       int
	Data         []byte
}

type scanResults struct {
	matches map[matchConditionPath]match
}

func (e *customRuleEvaluationImpl) scanTarget(m matchVariable, content string, results *scanResults) (err error) {
	cg, ok := e.engine.conditionGroups[m]
	if !ok {
		// There were no conditions that needed this target
		return
	}

	for _, st := range cg.sameTransformations {
		contentTransformed := applyTransformations(content, st.transformations)

		// This deals with Regex, BeginsWith, EndsWith, Contains, Equals
		if st.multiRegexEngine != nil {
			var mrematches []waf.MultiRegexEngineMatch
			mrematches, err = st.multiRegexEngine.Scan([]byte(contentTransformed), (*e.scratchSpacesInstance)[&st.multiRegexEngine])
			if err != nil {
				return
			}

			for _, mrematch := range mrematches {
				mcp := st.backRefs[mrematch.ID]
				if _, ok := results.matches[mcp]; ok {
					// A match for this condition was already found
					continue
				}

				results.matches[mcp] = match{
					VariableName: m.variableName,
					FieldName:    m.selector,
					StartPos:     mrematch.StartPos,
					EndPos:       mrematch.EndPos,
					Data:         mrematch.Data,
				}
			}
		}

		// Evaluate remaining conditions that are not evaluated by the regex engine
		rules := e.engine.rules
		for _, mcp := range st.matchConditionPaths {
			mc := rules[mcp.ruleIdx].MatchConditions()[mcp.mcIdx]
			op := mc.Operator()

			for _, mvar := range mc.MatchVariables() {
				if !(mvar.VariableName() == m.variableName && mvar.Selector() == m.selector) {
					continue
				}

				for _, mval := range mc.MatchValues() {
					switch op {
					case "Regex", "BeginsWith", "EndsWith", "Contains", "Equals":
						// Already dealt with above
					case "IPMatch":
						var prefix, mask uint32
						prefix, mask, err = ipaddresses.ParseCIDR(mval)
						if err != nil {
							// If a IP match operation was attempted a match value that was not an IP, just treat this as a non-match
							continue
						}

						var ip uint32
						ip, err = ipaddresses.ParseIPAddress(contentTransformed)
						if err != nil {
							// If a IP match operation was attempted an input value that was not an IP, just treat this as a non-match
							continue
						}

						if prefix&mask == ip&mask {
							results.matches[mcp] = match{StartPos: 0, EndPos: len(contentTransformed) - 1, Data: []byte(contentTransformed)}
						}

					case "GeoMatch":
						// Example content: "8.8.8.8:80,8.8.4.4,10.10.10.10:443".
						for _, ipPortFromContent := range strings.Split(contentTransformed, ",") {
							ipFromContent := strings.TrimSpace(strings.Split(ipPortFromContent, ":")[0])
							contentCountryCode := e.engine.geoDB.GeoLookup(ipFromContent)

							if strings.EqualFold(contentCountryCode, mval) {
								results.matches[mcp] = match{Data: []byte(contentCountryCode)}
								return
							}
						}

					case "LessThan", "GreaterThan", "LessThanOrEqual", "GreaterThanOrEqual":
						matchValNum, atoierr := strconv.Atoi(mval)
						if atoierr != nil {
							// If a numerical operation was attempted with a non-numerical value, just treat this as a non-match
							continue
						}

						contentNum, atoierr := strconv.Atoi(contentTransformed)
						if atoierr != nil {
							// If a numerical operation was attempted with a non-numerical value, just treat this as a non-match
							continue
						}

						isMatch := false
						switch op {
						case "LessThan":
							isMatch = contentNum < matchValNum
						case "GreaterThan":
							isMatch = contentNum > matchValNum
						case "LessThanOrEqual":
							isMatch = contentNum <= matchValNum
						case "GreaterThanOrEqual":
							isMatch = contentNum >= matchValNum
						}

						if isMatch {
							results.matches[mcp] = match{StartPos: 0, EndPos: len(contentTransformed) - 1, Data: []byte(contentTransformed)}
						}
					}
				}
			}
		}
	}

	return
}

func (e *customRuleEvaluationImpl) scanCookies(c string, results *scanResults) (err error) {
	// Use Go's http.Request to parse the cookies.
	goReq := &http.Request{Header: http.Header{"Cookie": []string{c}}}
	cookies := goReq.Cookies()
	for _, cookie := range cookies {
		err = e.scanTarget(matchVariable{variableName: "RequestCookies"}, cookie.Value, results)
		if err != nil {
			return
		}

		err = e.scanTarget(matchVariable{variableName: "RequestCookies", selector: cookie.Name}, cookie.Value, results)
		if err != nil {
			return
		}
	}

	return
}

func applyTransformations(s string, transformations []string) string {
	// TODO implement a trie for caching already done transformations
	for _, t := range transformations {
		// TODO implement all transformations
		switch t {
		case "Lowercase":
			s = strings.ToLower(s)
		case "Trim":
			s = strings.TrimSpace(s)
		case "UrlDecode":
			s = encoding.WeakURLUnescape(s)
		case "UrlEncode":
			s = url.PathEscape(s)
		case "RemoveNulls":
			if strings.Contains(s, "\x00") {
				s = strings.Replace(s, "\x00", "", -1)
			}
		case "HtmlEntityDecode":
			if strings.Contains(s, "&") {
				s = html.UnescapeString(s)
				// TODO ensure this aligns with the intended htmlEntityDecode functionality of SecRule-lang: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#htmlEntityDecode
				// TODO read https://golang.org/pkg/html/#UnescapeString closely. We need to think about if the unicode behaviour here is correct for SecRule-lang.
			}
		}
	}

	return s
}

func stringSliceEquals(a []string, b []string) bool {
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
