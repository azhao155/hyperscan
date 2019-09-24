package waf

// IPReputationEngine compares incoming requests' IPs to a list of known malicious IPs.
type IPReputationEngine interface {
	EvalRequest(req IPReputationEngineHTTPRequest) bool
	PutIPReputationList([]string)
}

// IPReputationEngineHTTPRequest represents an HTTP request to be evaluated by IPReputationEngine.
type IPReputationEngineHTTPRequest interface {
	RemoteAddr() string
}
