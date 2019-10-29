package waf

import "github.com/rs/zerolog"

// CustomRuleEngineFactory creates an engine to process customer specified rules.
type CustomRuleEngineFactory interface {
	NewEngine(c CustomRuleConfig) (CustomRuleEngine, error)
}

// CustomRuleEngine is a WAF engine compatible with a subset of the ModCustomurity CustomRule language.
type CustomRuleEngine interface {
	NewEvaluation(logger zerolog.Logger, resultsLogger CustomRuleResultsLogger, req HTTPRequest) CustomRuleEvaluation
}

// CustomRuleEvaluation is a run session of the CustomRule engine for a single specific HTTP request.
type CustomRuleEvaluation interface {
	ScanHeaders() error
	ScanBodyField(contentType ContentType, fieldName string, data string) error
	EvalRules() (wafDecision Decision)
	Close()
}

// CustomRuleResultsLogger is where the custom rules engine writes the high level customer facing results.
type CustomRuleResultsLogger interface {
	CustomRuleTriggered(customRuleID string, action string, matchedConditions []ResultsLoggerCustomRulesMatchedConditions)
}

// ResultsLoggerCustomRulesMatchedConditions describes how a condition got matched, so the ResultsLogger can communicate this to the user.
type ResultsLoggerCustomRulesMatchedConditions struct {
	ConditionIndex int
	VariableName   string
	FieldName      string
	MatchedValue   string
}
