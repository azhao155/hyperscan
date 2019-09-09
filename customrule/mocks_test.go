package customrule

import (
	"azwaf/waf"
	"io"
)

type mockWafHTTPRequest struct {
	uri        string
	bodyReader io.Reader
	headers    []waf.HeaderPair
}

func (r *mockWafHTTPRequest) Method() string             { return "GET" }
func (r *mockWafHTTPRequest) URI() string                { return r.uri }
func (r *mockWafHTTPRequest) ConfigID() string           { return "SecRuleConfig1" }
func (r *mockWafHTTPRequest) CustomRuleConfigID() string { return "CustomRuleConfig1" }
func (r *mockWafHTTPRequest) Headers() []waf.HeaderPair  { return r.headers }
func (r *mockWafHTTPRequest) BodyReader() io.Reader      { return r.bodyReader }

type mockHeaderPair struct {
	k string
	v string
}

func (h *mockHeaderPair) Key() string   { return h.k }
func (h *mockHeaderPair) Value() string { return h.v }

type mockMatchVariable struct {
	variableName string
	selector     string
}

func (mmvar mockMatchVariable) VariableName() string {
	return mmvar.variableName
}

func (mmvar mockMatchVariable) Selector() string {
	return mmvar.selector
}

type mockMatchCondition struct {
	matchVariables  []waf.MatchVariable
	operator        string
	negateCondition bool
	matchValues     []string
	transforms      []string
}

func (mmc mockMatchCondition) MatchVariables() []waf.MatchVariable {
	return mmc.matchVariables
}

func (mmc mockMatchCondition) Operator() string {
	return mmc.operator
}

func (mmc mockMatchCondition) NegateCondition() bool {
	return mmc.negateCondition
}

func (mmc mockMatchCondition) MatchValues() []string {
	return mmc.matchValues
}

func (mmc mockMatchCondition) Transforms() []string {
	return mmc.transforms
}

type mockCustomRule struct {
	name            string
	priority        int
	ruleType        string
	matchConditions []waf.MatchCondition
	action          string
}

func (mcr mockCustomRule) Name() string {
	return mcr.name
}

func (mcr mockCustomRule) Priority() int {
	return mcr.priority
}

func (mcr mockCustomRule) RuleType() string {
	return mcr.ruleType
}

func (mcr mockCustomRule) MatchConditions() []waf.MatchCondition {
	return mcr.matchConditions
}

func (mcr mockCustomRule) Action() string {
	return mcr.action
}

type mockCustomRuleConfig struct {
	customRules []waf.CustomRule
}

func (mcrc mockCustomRuleConfig) CustomRules() []waf.CustomRule {
	return mcrc.customRules
}
