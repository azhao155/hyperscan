package logging

import (
	"azwaf/secrule"
	"azwaf/waf"
	"encoding/json"
	"github.com/rs/zerolog/log"
	"strconv"
)

type customerFirewallLogEntry struct {
	InstanceID     string                          `json:"instanceId"`
	ClientIP       string                          `json:"clientIp"`
	ClientPort     string                          `json:"clientPort"`
	RequestURI     string                          `json:"requestUri"`
	RuleSetType    string                          `json:"ruleSetType"`
	RuleSetVersion string                          `json:"ruleSetVersion"`
	RuleID         string                          `json:"ruleId"`
	RuleGroup      string                          `json:"ruleGroup"`
	Message        string                          `json:"message"`
	Action         string                          `json:"action"`
	Site           string                          `json:"site"`
	Details        customerFirewallLogDetailsEntry `json:"details"`
	Hostname       string                          `json:"hostname"`
	TransactionID  string                          `json:"transactionId"`
}

type customerFirewallLogDetailsEntry struct {
	Message string `json:"message"`
	Data    string `json:"data"`
	File    string `json:"file"`
	Line    string `json:"line"`
}

// NewZerologResultsLogger creates a results logger that creates log messages like the ones we want to send to the customer, but just outputs them to Zerolog.
func NewZerologResultsLogger() secrule.ResultsLogger {
	return &zerologResultsLogger{}
}

type zerologResultsLogger struct{}

func (l *zerologResultsLogger) SecRuleTriggered(request waf.HTTPRequest, stmt secrule.Statement, action string, msg string, logData string) {
	// TODO probably dont take msg as a param as we can extract it from stmt instead. Maybe only take logData as param.

	var ruleID int
	switch stmt := stmt.(type) {
	case *secrule.Rule:
		ruleID = stmt.ID
	case *secrule.ActionStmt:
		ruleID = stmt.ID
	}

	// TODO fill entire struct
	c := &customerFirewallLogEntry{
		RequestURI: request.URI(),
		RuleID:     strconv.Itoa(ruleID),
		Message:    msg,
		Action:     action,
		Details: customerFirewallLogDetailsEntry{
			Message: logData,
		},
	}

	bb, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		log.Error().Err(err).Msg("Error while marshaling JSON results log")
	}

	log.Info().Msgf("Customer facing log: %s\n", bb)
}
