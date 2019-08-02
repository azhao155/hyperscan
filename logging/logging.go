package logging

import (
	"azwaf/secrule"
	"azwaf/waf"
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog"
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
func NewZerologResultsLogger(logger zerolog.Logger) (secrule.ResultsLogger, waf.ResultsLogger) {
	r := &zerologResultsLogger{logger: logger}
	return r, r
}

type zerologResultsLogger struct {
	logger zerolog.Logger
}

func (l *zerologResultsLogger) SecRuleTriggered(request waf.HTTPRequest, stmt secrule.Statement, action string, msg string, logData string) {
	// TODO probably dont take msg as a param as we can extract it from stmt instead. Maybe only take logData as param.

	var ruleID int
	switch stmt := stmt.(type) {
	case *secrule.Rule:
		ruleID = stmt.ID
	case *secrule.ActionStmt:
		ruleID = stmt.ID
	}

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
		l.logger.Error().Err(err).Msg("Error while marshaling JSON results log")
	}

	l.logger.Info().Msgf("Customer facing log:\n%s\n", bb)
}

func (l *zerologResultsLogger) FieldBytesLimitExceeded(request waf.HTTPRequest, limit int) {
	l.bytesLimitExceeded(request, fmt.Sprintf("Request body contained a field longer than the limit (%d bytes)", limit))
}
func (l *zerologResultsLogger) PausableBytesLimitExceeded(request waf.HTTPRequest, limit int) {
	l.bytesLimitExceeded(request, fmt.Sprintf("Request body length (excluding file upload fields) exceeded the limit (%d bytes)", limit))
}
func (l *zerologResultsLogger) TotalBytesLimitExceeded(request waf.HTTPRequest, limit int) {
	l.bytesLimitExceeded(request, fmt.Sprintf("Request body length exceeded the limit (%d bytes)", limit))
}

func (l *zerologResultsLogger) bytesLimitExceeded(request waf.HTTPRequest, msg string) {
	c := &customerFirewallLogEntry{
		RequestURI: request.URI(),
		Message:    msg,
		Action:     "Blocked",
		Details:    customerFirewallLogDetailsEntry{},
	}

	bb, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		l.logger.Error().Err(err).Msg("Error while marshaling JSON results log")
	}

	l.logger.Info().Msgf("Customer facing log:\n%s\n", bb)
}

func (l *zerologResultsLogger) BodyParseError(request waf.HTTPRequest, err error) {
	c := &customerFirewallLogEntry{
		RequestURI: request.URI(),
		Message:    fmt.Sprintf("Request body scanning error"),
		Action:     "Blocked",
		Details: customerFirewallLogDetailsEntry{
			Message: err.Error(),
		},
	}

	bb, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		l.logger.Error().Err(err).Msg("Error while marshaling JSON results log")
	}

	l.logger.Info().Msgf("Customer facing log:\n%s\n", bb)
}
