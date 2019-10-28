package customrule

import (
	"azwaf/waf"
)

// ResultsLogger is where the SecRule engine writes the high level customer facing results.
type ResultsLogger interface {
	CustomRuleTriggered(request ResultsLoggerHTTPRequest, rule waf.CustomRule, matchedConditions []ResultsLoggerMatchedConditions)
}

// ResultsLoggerHTTPRequest represents an HTTP request to be logged by ResultsLogger.
// TODO delete this interface, and instead create a fresh results logger based on each request, and pass it to NewEvaluation
type ResultsLoggerHTTPRequest interface {
	ConfigID() string
	URI() string
	RemoteAddr() string
	Headers() []waf.HeaderPair
	LogMetaData() waf.RequestLogMetaData
	TransactionID() string
}

// ResultsLoggerMatchedConditions describes how a condition got matched, so the ResultsLogger can communicate this to the user.
type ResultsLoggerMatchedConditions struct {
	ConditionIndex int
	VariableName   string
	FieldName      string
	MatchedValue   string
}
