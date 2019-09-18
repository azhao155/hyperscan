package waf

import "github.com/rs/zerolog"

// CustomRuleEngineFactory creates an engine to process customer specified rules.
type CustomRuleEngineFactory interface {
	NewEngine(c CustomRuleConfig) (CustomRuleEngine, error)
}

// CustomRuleEngine is a WAF engine compatible with a subset of the ModCustomurity CustomRule language.
type CustomRuleEngine interface {
	NewEvaluation(logger zerolog.Logger, req HTTPRequest) CustomRuleEvaluation
}

// CustomRuleEvaluation is a run session of the CustomRule engine for a single specific HTTP request.
type CustomRuleEvaluation interface {
	ScanHeaders() error
	ScanBodyField(contentType ContentType, fieldName string, data string) error
	EvalRules() (wafDecision Decision)
	Close()
}
