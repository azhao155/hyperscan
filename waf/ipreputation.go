package waf

// IPReputationEngine compares incoming requests' IPs to a list of known malicious IPs.
type IPReputationEngine interface {
	EvalRequest(req IPReputationEngineHTTPRequest, resultsLogger IPReputationResultsLogger) Decision
	PutIPReputationList([]string)
}

// IPReputationEngineHTTPRequest represents an HTTP request to be evaluated by IPReputationEngine.
type IPReputationEngineHTTPRequest interface {
	RemoteAddr() string
	Headers() []HeaderPair
}

// IPReputationResultsLogger is where the IP reputation engine writes the high level customer facing results.
type IPReputationResultsLogger interface {
	IPReputationTriggered()
}
