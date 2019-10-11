package logging

import (
	"azwaf/customrules2"
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

type filelogResultsLoggerImpl struct {
	fileSystem   LogFileSystem
	file         LogFile
	logger       zerolog.Logger
	writelogline chan []byte
	writeDone    chan bool
	metaData     waf.ConfigLogMetaData
}

// FilelogResultsLogger writes customer facing logs to a file.
type FilelogResultsLogger interface {
	FieldBytesLimitExceeded(request waf.ResultsLoggerHTTPRequest, limit int)
	PausableBytesLimitExceeded(request waf.ResultsLoggerHTTPRequest, limit int)
	TotalBytesLimitExceeded(request waf.ResultsLoggerHTTPRequest, limit int)
	BodyParseError(request waf.ResultsLoggerHTTPRequest, err error)
	SetLogMetaData(data waf.ConfigLogMetaData)
	SecRuleTriggered(request secrule.ResultsLoggerHTTPRequest, stmt secrule.Statement, action string, msg string, logData string)
	IPReputationTriggered(request ipreputation.ResultsLoggerHTTPRequest)
	CustomRuleTriggered(request customrules2.ResultsLoggerHTTPRequest, rule waf.CustomRule)
}

// NewFileResultsLogger creates a results logger that write log messages to file.
func NewFileResultsLogger(fileSystem LogFileSystem, logger zerolog.Logger) (FilelogResultsLogger, error) {
	r := &filelogResultsLoggerImpl{fileSystem: fileSystem, logger: logger}

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

func (l *filelogResultsLoggerImpl) SecRuleTriggered(request secrule.ResultsLoggerHTTPRequest, stmt secrule.Statement, action string, msg string, logData string) {
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

func (l *filelogResultsLoggerImpl) IPReputationTriggered(request ipreputation.ResultsLoggerHTTPRequest) {
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

func (l *filelogResultsLoggerImpl) FieldBytesLimitExceeded(request waf.ResultsLoggerHTTPRequest, limit int) {
	l.bytesLimitExceeded(request, fmt.Sprintf("Request body contained a field longer than the limit (%d bytes)", limit))
}

func (l *filelogResultsLoggerImpl) PausableBytesLimitExceeded(request waf.ResultsLoggerHTTPRequest, limit int) {
	l.bytesLimitExceeded(request, fmt.Sprintf("Request body length (excluding file upload fields) exceeded the limit (%d bytes)", limit))
}

func (l *filelogResultsLoggerImpl) TotalBytesLimitExceeded(request waf.ResultsLoggerHTTPRequest, limit int) {
	l.bytesLimitExceeded(request, fmt.Sprintf("Request body length exceeded the limit (%d bytes)", limit))
}

func (l *filelogResultsLoggerImpl) bytesLimitExceeded(request waf.ResultsLoggerHTTPRequest, msg string) {
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

func (l *filelogResultsLoggerImpl) BodyParseError(request waf.ResultsLoggerHTTPRequest, err error) {
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

func (l *filelogResultsLoggerImpl) CustomRuleTriggered(request customrules2.ResultsLoggerHTTPRequest, rule waf.CustomRule) {
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

func (l *filelogResultsLoggerImpl) sendLog(data interface{}) {
	bb, err := json.Marshal(data)
	if err != nil {
		l.logger.Error().Err(err).Msg("Error while marshaling JSON results log")
	}

	l.writelogline <- bb
	<-l.writeDone
}

func (l *filelogResultsLoggerImpl) SetLogMetaData(metaData waf.ConfigLogMetaData) {
	l.metaData = metaData
}
