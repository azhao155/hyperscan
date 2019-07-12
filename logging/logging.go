package logging

import (
	"azwaf/secrule"
	"azwaf/waf"
	"encoding/json"
	log "github.com/sirupsen/logrus"
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

// NewLogrusResultsLogger creates a results logger that creates log messages like the ones we want to send to the customer, but just outputs them to Logrus.
func NewLogrusResultsLogger() secrule.ResultsLogger {
	return &logrusResultsLogger{}
}

type logrusResultsLogger struct{}

func (l *logrusResultsLogger) SecRuleTriggered(request waf.HTTPRequest, stmt secrule.Statement, action string, msg string) {
	ruleID := 0
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
		Action:     action,
	}

	bb, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		log.WithField("error", err).Error("Error while marshaling JSON results log")
	}

	log.Infof("Customer facing log:\n%s", bb)
}
