package waf

// CustomRuleConfig is CustomRule Engine config
type CustomRuleConfig interface {
	CustomRules() []CustomRule
}

// CustomRule is definition of custom rule
type CustomRule interface {
	Name() string
	Priority() int
	RuleType() string
	MatchConditions() []MatchCondition
	Action() string
}

// MatchCondition is the condition defined for custom rules
type MatchCondition interface {
	MatchVariables() []MatchVariable
	Operator() string
	NegateCondition() bool
	MatchValues() []string
	Transforms() []string
}

// MatchVariable is the match variable for custom rules
type MatchVariable interface {
	VariableName() string
	Selector() string
}
