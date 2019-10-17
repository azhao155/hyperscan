package ipreputation

import "azwaf/waf"

// ResultsLogger is where the SecRule engine writes the high level customer facing results.
type ResultsLogger interface {
	IPReputationTriggered(request ResultsLoggerHTTPRequest)
}

// ResultsLoggerHTTPRequest represents an HTTP request to be logged by ResultsLogger.
type ResultsLoggerHTTPRequest interface {
	waf.ResultsLoggerHTTPRequest
}
