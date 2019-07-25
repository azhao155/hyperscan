package customrule

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
