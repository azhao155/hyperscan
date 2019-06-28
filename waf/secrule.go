package waf

// SecRuleEngineFactory creates SecRuleEngines. This makes mocking possible when testing.
type SecRuleEngineFactory interface {
	NewEngine(r RuleSetID) (SecRuleEngine, error)
}

// SecRuleEngine is compatible with a subset of the ModSecurity SecRule language.
type SecRuleEngine interface {
	EvalRequest(req HTTPRequest) bool
}

// RuleSetID identifies which rule set to initialize the engine with.
type RuleSetID string
