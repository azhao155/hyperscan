package customrule

import (
	"azwaf/secrule"
	"azwaf/waf"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

var targetsMap = map[string]string{
	"RemoteAddr":     "REMOTE_ADDR",
	"RequestMethod":  "REQUEST_METHOD",
	"QueryString":    "QUERY_STRING",
	"PostArgs":       "ARGS_POST",
	"RequestUri":     "REQUEST_URI",
	"RequestHeaders": "REQUEST_HEADERS",
	"RequestBody":    "REQUEST_BODY",
	"RequestCookies": "REQUEST_COOKIES",
}

var operatorsMap = map[string]secrule.Operator{

	"IPMatch":            secrule.IPMatch,
	"Equals":             secrule.Rx,
	"Contains":           secrule.Rx,
	"LessThan":           secrule.Lt,
	"LessThanOrEqual":    secrule.Le,
	"GreaterThan":        secrule.Gt,
	"GreaterThanOrEqual": secrule.Ge,
	"BeginsWith":         secrule.Rx,
	"EndsWith":           secrule.Rx,
	"Regex":              secrule.Rx,
	"GeoMatch":           secrule.CallBack,
}

var transformMap = map[string]secrule.Transformation{

	"Lowercase":        secrule.Lowercase,
	"Trim":             secrule.Trim,
	"UrlDecode":        secrule.URLDecode,
	"UrlEncode":        secrule.URLEncode,
	"RemoveNulls":      secrule.RemoveNulls,
	"HtmlEntityDecode": secrule.HTMLEntityDecode,
}

func (rl *ruleLoader) toSecRule(cr waf.CustomRule) (st secrule.Statement, err error) {

	rule := &secrule.Rule{
		ID:    int(cr.Priority()),
		Phase: 0,
	}

	sri := secrule.RuleItem{}
	for _, mc := range cr.MatchConditions() {
		sri, err = rl.toSecRuleItem(mc)
		if err != nil {
			return
		}
		rule.Items = append(rule.Items, sri)
	}

	var action secrule.Action
	switch cr.Action() {
	case "Allow":
		action = &secrule.AllowAction{}
	case "Block":
		action = &secrule.BlockAction{}
	case "Log":
		action = &secrule.LogAction{}
	default:
		err = fmt.Errorf("received unsupported action %s", cr.Action())
		return
	}

	rule.Items[0].Actions = append(rule.Items[0].Actions, action)

	st = rule
	return
}

func (rl *ruleLoader) toSecRuleItem(mc waf.MatchCondition) (ri secrule.RuleItem, err error) {
	t := ""
	for _, mv := range mc.MatchVariables() {
		t, err = rl.toSecRuleTarget(mv)
		if err != nil {
			return
		}
		ri.Predicate.Targets = append(ri.Predicate.Targets, t)
	}

	ri.Predicate.Op = operatorsMap[mc.Operator()]
	if ri.Predicate.Op == secrule.CallBack {
		ri.Predicate.CallBackOpFunc = rl.toOperatorFunc(mc.Operator())
	}
	ri.Predicate.Neg = mc.NegateCondition()
	ri.Predicate.Val = rl.toSecRuleMatchValue(mc)

	for _, tr := range mc.Transforms() {
		ri.Transformations = append(ri.Transformations, transformMap[tr])
	}

	return
}

func (rl *ruleLoader) toSecRuleMatchValue(mc waf.MatchCondition) (mv string) {

	var ev []string
	min := math.MaxInt64
	max := 0
	for _, v := range mc.MatchValues() {
		if n, ok := strconv.Atoi(v); ok == nil {
			if n < min {
				min = n
			}

			if n > max {
				max = n
			}
		}
		ev = append(ev, regexp.QuoteMeta(v))

	}

	//TODO: need to be aware of the HyperScan regex limit, consider splitting into multiple rules
	switch mc.Operator() {
	case "IPMatch":
		mv = strings.Join(mc.MatchValues(), ",")
	case "Equals":
		mv = "^(" + strings.Join(ev, "|") + ")$"
	case "Contains":
		mv = "(" + strings.Join(ev, "|") + ")"
	case "BeginsWith":
		mv = "^(" + strings.Join(ev, "|") + ")"
	case "EndsWith":
		mv = "(" + strings.Join(ev, "|") + ")$"
	case "LessThan", "LessThanOrEqual":
		mv = strconv.Itoa(max)
	case "GreaterThan", "GreaterThanOrEqual":
		mv = strconv.Itoa(min)
	}

	return
}

func (rl *ruleLoader) toSecRuleTarget(mv waf.MatchVariable) (target string, err error) {
	target = targetsMap[mv.VariableName()]
	if mv.Selector() != "" {
		target = target + ":" + regexp.QuoteMeta(mv.Selector())
	}
	return
}
