package logging

import (
	"azwaf/customrule"
	"azwaf/ipreputation"
	"azwaf/secrule"
	"azwaf/waf"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/rs/zerolog"
)

// Path is the azwaf log path
const Path = "/appgwroot/log/azwaf/"

// FileName is the azwaf log file name
const FileName = "waf_json.log"

// FilelogResultsLogger writes customer facing logs to a file.
type FilelogResultsLogger struct {
	fileSystem   LogFileSystem
	file         LogFile
	logger       zerolog.Logger
	writelogline chan []byte
	writeDone    chan bool
	metaData     waf.ConfigLogMetaData
}

// NewFileResultsLogger creates a results logger that write log messages to file.
func NewFileResultsLogger(fileSystem LogFileSystem, logger zerolog.Logger) (*FilelogResultsLogger, error) {
	r := &FilelogResultsLogger{fileSystem: fileSystem, logger: logger}

	err := fileSystem.MkDir(Path)
	if err != nil {
		logger.Error().Err(err).Str("path", Path).Msg("Failed to create the directory while initializing")
		return nil, err
	}

	r.file, err = fileSystem.Open(Path + FileName)
	if err != nil {
		logger.Error().Err(err).Str("file", Path+FileName).Msg("Failed to open the file at initiation")
		return nil, err
	}

	r.writelogline = make(chan []byte)
	r.writeDone = make(chan bool)
	go func() {
		for v := range r.writelogline {
			r.file.Append(v)
			r.file.Append([]byte("\n"))
			r.writeDone <- true
		}
	}()

	return r, nil
}

// SecRuleTriggered is to be called when a SecRule was triggered.
func (l *FilelogResultsLogger) SecRuleTriggered(request secrule.ResultsLoggerHTTPRequest, stmt secrule.Statement, action string, msg string, logData string) {
	var ruleID int
	switch stmt := stmt.(type) {
	case *secrule.Rule:
		ruleID = stmt.ID
	case *secrule.ActionStmt:
		ruleID = stmt.ID
	}

	rID := ""
	iID := ""
	if l.metaData != nil {
		rID = l.metaData.ResourceID()
		iID = l.metaData.InstanceID()
	}

	var policyScope, policyScopeName string
	if request.LogMetaData() != nil {
		policyScope = request.LogMetaData().Scope()
		policyScopeName = request.LogMetaData().ScopeName()
	}

	c := customerFirewallLogEntryProperty{
		InstanceID: iID,
		RequestURI: request.URI(),
		RuleID:     strconv.Itoa(ruleID),
		Message:    msg,
		Action:     action,
		Details: customerFirewallLogDetailsEntry{
			Message: logData,
		},
		TransactionID:   request.TransactionID(),
		PolicyID:        request.ConfigID(),
		PolicyScope:     policyScope,
		PolicyScopeName: policyScopeName,
	}

	lg := &customerFirewallLogEntry{
		ResourceID:    rID,
		OperationName: "ApplicationGatewayFirewall",
		Category:      "ApplicationGatewayFirewallLog",
		Properties:    c,
	}

	l.sendLog(lg)
}

// IPReputationTriggered is to be called when a the IP reputation engine resulted in a request being blocked.
func (l *FilelogResultsLogger) IPReputationTriggered(request ipreputation.ResultsLoggerHTTPRequest) {
	rID := ""
	iID := ""
	if l.metaData != nil {
		rID = l.metaData.ResourceID()
		iID = l.metaData.InstanceID()
	}

	var policyScope, policyScopeName string
	if request.LogMetaData() != nil {
		policyScope = request.LogMetaData().Scope()
		policyScopeName = request.LogMetaData().ScopeName()
	}

	c := customerFirewallIPReputationLogEntryProperty{
		InstanceID:      iID,
		RequestURI:      request.URI(),
		Message:         "IPReputationTriggered",
		Action:          "Blocked",
		TransactionID:   request.TransactionID(),
		PolicyID:        request.ConfigID(),
		PolicyScope:     policyScope,
		PolicyScopeName: policyScopeName,
	}

	lg := &customerFirewallIPReputationLogEntry{
		ResourceID:    rID,
		OperationName: "ApplicationGatewayFirewall",
		Category:      "ApplicationGatewayFirewallLog",
		Properties:    c,
	}

	l.sendLog(lg)
}

// FieldBytesLimitExceeded is to be called when the request body contained a field longer than the limit.
func (l *FilelogResultsLogger) FieldBytesLimitExceeded(request waf.ResultsLoggerHTTPRequest, limit int) {
	l.bytesLimitExceeded(request, fmt.Sprintf("Request body contained a field longer than the limit (%d bytes)", limit))
}

// PausableBytesLimitExceeded is to be called when the request body length (excluding file upload fields) exceeded the limit.
func (l *FilelogResultsLogger) PausableBytesLimitExceeded(request waf.ResultsLoggerHTTPRequest, limit int) {
	l.bytesLimitExceeded(request, fmt.Sprintf("Request body length (excluding file upload fields) exceeded the limit (%d bytes)", limit))
}

// TotalBytesLimitExceeded is to be called when the request body length exceeded the limit.
func (l *FilelogResultsLogger) TotalBytesLimitExceeded(request waf.ResultsLoggerHTTPRequest, limit int) {
	l.bytesLimitExceeded(request, fmt.Sprintf("Request body length exceeded the limit (%d bytes)", limit))
}

func (l *FilelogResultsLogger) bytesLimitExceeded(request waf.ResultsLoggerHTTPRequest, msg string) {
	rID := ""
	iID := ""
	if l.metaData != nil {
		rID = l.metaData.ResourceID()
		iID = l.metaData.InstanceID()
	}

	var policyScope, policyScopeName string
	if request.LogMetaData() != nil {
		policyScope = request.LogMetaData().Scope()
		policyScopeName = request.LogMetaData().ScopeName()
	}

	c := customerFirewallLimitExceedLogEntryProperty{
		InstanceID:      iID,
		RequestURI:      request.URI(),
		Message:         msg,
		Action:          "Blocked",
		TransactionID:   request.TransactionID(),
		PolicyID:        request.ConfigID(),
		PolicyScope:     policyScope,
		PolicyScopeName: policyScopeName,
	}

	lg := &customerFirewallLimitExceedLogEntry{
		ResourceID:    rID,
		OperationName: "ApplicationGatewayFirewall",
		Category:      "ApplicationGatewayFirewallLog",
		Properties:    c,
	}

	l.sendLog(lg)
}

// BodyParseError is to be called when the request body parser hit an error causing the request to be blocked.
func (l *FilelogResultsLogger) BodyParseError(request waf.ResultsLoggerHTTPRequest, err error) {
	rID := ""
	iID := ""
	if l.metaData != nil {
		rID = l.metaData.ResourceID()
		iID = l.metaData.InstanceID()
	}

	var policyScope, policyScopeName string
	if request.LogMetaData() != nil {
		policyScope = request.LogMetaData().Scope()
		policyScopeName = request.LogMetaData().ScopeName()
	}

	c := customerFirewallBodyParseLogEntryProperty{
		InstanceID:      iID,
		RequestURI:      request.URI(),
		Message:         fmt.Sprintf("Request body scanning error"),
		Action:          "Blocked",
		TransactionID:   request.TransactionID(),
		PolicyID:        request.ConfigID(),
		PolicyScope:     policyScope,
		PolicyScopeName: policyScopeName,
		Details: customerFirewallLogBodyParseDetailsEntry{
			Message: err.Error(),
		},
	}

	lg := &customerFirewallBodyParseLogEntry{
		ResourceID:    rID,
		OperationName: "ApplicationGatewayFirewall",
		Category:      "ApplicationGatewayFirewallLog",
		Properties:    c,
	}

	l.sendLog(lg)
}

// CustomRuleTriggered is to be called when a custom rule was triggered.
func (l *FilelogResultsLogger) CustomRuleTriggered(request customrule.ResultsLoggerHTTPRequest, rule waf.CustomRule) {
	rID := ""
	iID := ""
	if l.metaData != nil {
		rID = l.metaData.ResourceID()
		iID = l.metaData.InstanceID()
	}

	var policyScope, policyScopeName string
	if request.LogMetaData() != nil {
		policyScope = request.LogMetaData().Scope()
		policyScopeName = request.LogMetaData().ScopeName()
	}

	c := customerFirewallCustomRuleLogEntryProperties{
		InstanceID:      iID,
		RequestURI:      request.URI(),
		RuleSetType:     "Custom",
		RuleID:          rule.Name(),
		Action:          rule.Action(),
		TransactionID:   request.TransactionID(),
		PolicyID:        request.ConfigID(),
		PolicyScope:     policyScope,
		PolicyScopeName: policyScopeName,
	}

	lg := &customerFirewallCustomRuleLogEntry{
		ResourceID:    rID,
		OperationName: "ApplicationGatewayFirewall",
		Category:      "ApplicationGatewayFirewallLog",
		Properties:    c,
	}

	l.sendLog(lg)
}

func (l *FilelogResultsLogger) sendLog(data interface{}) {
	bb, err := json.Marshal(data)
	if err != nil {
		l.logger.Error().Err(err).Msg("Error while marshaling JSON results log")
	}

	l.writelogline <- bb
	<-l.writeDone
}

// SetLogMetaData is to be called during initialization to set data needed by the logger later.
func (l *FilelogResultsLogger) SetLogMetaData(metaData waf.ConfigLogMetaData) {
	l.metaData = metaData
}
