package waf

// IPReputationEngine compares incoming requests' IPs to a list of known malicious IPs.
type IPReputationEngine interface {
	EvalRequest(req HTTPRequest) bool
	PutIPReputationList([]string)
}
