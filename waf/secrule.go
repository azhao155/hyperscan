package waf

import "github.com/rs/zerolog"

// SecRuleEngineFactory creates SecRuleEngines. This makes mocking possible when testing.
type SecRuleEngineFactory interface {
	NewEngine(c SecRuleConfig) (SecRuleEngine, error)
}

// SecRuleEngine is a WAF engine compatible with a subset of the ModSecurity SecRule language.
type SecRuleEngine interface {
	NewEvaluation(logger zerolog.Logger, resultsLogger SecRuleResultsLogger, req HTTPRequest, reqBodyType ReqBodyType) SecRuleEvaluation
}

// SecRuleEvaluation is a session of the SecRule engine for a single specific HTTP request.
type SecRuleEvaluation interface {
	ScanHeaders() error
	ScanBodyField(contentType FieldContentType, fieldName string, data string) error
	EvalRulesPhase1() (wafDecision Decision)
	EvalRulesPhase2to5() (wafDecision Decision)
	AlsoScanFullRawRequestBody() bool
	BodyParseErrorOccurred()
	Close()
}

// RuleSetID identifies which rule set to initialize the engine with.
type RuleSetID string

// SecRuleResultsLogger is where the SecRule engine writes the high level customer facing results.
type SecRuleResultsLogger interface {
	SecRuleTriggered(ruleID int, decision Decision, msg string, logData string, ruleSetID RuleSetID)
}
