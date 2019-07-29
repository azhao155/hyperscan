package customrule

import (
	"azwaf/secrule"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// MatchVariable identifies the entity of the HTTP request that needs to be matched.
type MatchVariable struct {
	VariableName string `json:"variableName"`
	Selector     string `json:"selector"`
}

// MatchCondition specifies the condition that if satisfied causes the Action to run.
type MatchCondition struct {
	MatchVariables []MatchVariable `json:"matchVariables"`
	Operator       string          `json:"operator"`
	Negate         bool            `json:"negationCondition"`
	MatchValues    []string        `json:"matchValues"`
	Transforms     []string        `json:"transforms"`
}

// CustomRule specifies the customer specified rule that needs to run as part of WAF.
type CustomRule struct {
	Name            string           `json:"name"`
	Priority        int              `json:"priority"`
	RuleType        string           `json:"ruleType"`
	Action          string           `json:"action"`
	MatchConditions []MatchCondition `json:"matchConditions"`
}

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
}

var transformMap = map[string]secrule.Transformation{

	"Lowercase":        secrule.Lowercase,
	"Trim":             secrule.Trim,
	"UrlDecode":        secrule.URLDecode,
	"UrlEncode":        secrule.URLEncode,
	"RemoveNulls":      secrule.RemoveNulls,
	"HtmlEntityDecode": secrule.HTMLEntityDecode,
}

func (cr *CustomRule) toSecRule() (st secrule.Statement, err error) {

	rule := &secrule.Rule{
		ID:    cr.Priority,
		Phase: 0,
	}

	sri := secrule.RuleItem{}
	for _, mc := range cr.MatchConditions {
		sri, err = mc.toSecRuleItem()
		if err != nil {
			return
		}
		rule.Items = append(rule.Items, sri)
	}

	var action secrule.Action
	switch cr.Action {
	case "Allow":
		action = &secrule.AllowAction{}
	case "Block":
		action = &secrule.BlockAction{}
	case "Log":
		action = &secrule.LogAction{}
	default:
		err = fmt.Errorf("received unsupported action %s", cr.Action)
		return
	}

	rule.Items[0].Actions = append(rule.Items[0].Actions, action)

	st = rule
	return
}

func (mc *MatchCondition) toSecRuleItem() (ri secrule.RuleItem, err error) {
	t := ""
	for _, mv := range mc.MatchVariables {
		t, err = mv.toSecRuleTarget()
		if err != nil {
			return
		}
		ri.Predicate.Targets = append(ri.Predicate.Targets, t)
	}

	ri.Predicate.Op = operatorsMap[mc.Operator]
	ri.Predicate.Neg = mc.Negate
	ri.Predicate.Val = mc.toSecRuleMatchValue()

	for _, tr := range mc.Transforms {
		ri.Transformations = append(ri.Transformations, transformMap[tr])
	}

	return
}

func (mc *MatchCondition) toSecRuleMatchValue() (mv string) {

	var ev []string
	min := math.MaxInt64
	max := 0
	for _, v := range mc.MatchValues {
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
	switch mc.Operator {
	case "IPMatch":
		mv = strings.Join(mc.MatchValues, ",")
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

func (mv *MatchVariable) toSecRuleTarget() (target string, err error) {
	target = targetsMap[mv.VariableName]
	if mv.Selector != "" {
		target = target + ":" + regexp.QuoteMeta(mv.Selector)
	}
	return
}
