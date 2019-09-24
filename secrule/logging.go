package secrule

import "azwaf/waf"

// ResultsLogger is where the SecRule engine writes the high level customer facing results.
type ResultsLogger interface {
	SecRuleTriggered(request ResultsLoggerHTTPRequest, stmt Statement, action string, msg string, logData string)
}

// ResultsLoggerHTTPRequest represents an HTTP request to be logged by ResultsLogger.
type ResultsLoggerHTTPRequest interface {
	ConfigID() string
	URI() string
	LogMetaData() waf.RequestLogMetaData
	TransactionID() string
}
