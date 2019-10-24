package waf

import "github.com/rs/zerolog"

// SecRuleEngineFactory creates SecRuleEngines. This makes mocking possible when testing.
type SecRuleEngineFactory interface {
	NewEngine(c SecRuleConfig) (SecRuleEngine, error)
}

// SecRuleEngine is a WAF engine compatible with a subset of the ModSecurity SecRule language.
type SecRuleEngine interface {
	NewEvaluation(logger zerolog.Logger, req HTTPRequest) SecRuleEvaluation
	UsesFullRawRequestBody() bool
}

// SecRuleEvaluation is a session of the SecRule engine for a single specific HTTP request.
type SecRuleEvaluation interface {
	ScanHeaders() error
	ScanBodyField(contentType ContentType, fieldName string, data string) error
	EvalRules() (wafDecision Decision)
	Close()
}

// RuleSetID identifies which rule set to initialize the engine with.
type RuleSetID string
