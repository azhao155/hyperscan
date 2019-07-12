package secrule

import "azwaf/waf"

// ResultsLogger is where the SecRule engine writes the high level customer facing results.
type ResultsLogger interface {
	SecRuleTriggered(request waf.HTTPRequest, stmt Statement, action string, msg string)
}
