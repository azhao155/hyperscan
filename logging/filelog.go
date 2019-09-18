package logging

import (
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

type filelogResultsLogger struct {
	fileSystem   LogFileSystem
	file         LogFile
	logger       zerolog.Logger
	writelogline chan []byte
	writeDone    chan bool
	metaData     waf.ConfigLogMetaData
}

// NewFileResultsLogger creates a results logger that write log messages to file.
func NewFileResultsLogger(fileSystem LogFileSystem, logger zerolog.Logger) (secrule.ResultsLogger, waf.ResultsLogger, error) {
	r := &filelogResultsLogger{fileSystem: fileSystem, logger: logger}

	err := fileSystem.MkDir(Path)
	if err != nil {
		logger.Error().Err(err).Str("path", Path).Msg("Failed to create the directory while initializing")
		return nil, nil, err
	}

	r.file, err = fileSystem.Open(Path + FileName)
	if err != nil {
		logger.Error().Err(err).Str("file", Path+FileName).Msg("Failed to open the file at initiation")
		return nil, nil, err
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

	return r, r, nil
}

func (l *filelogResultsLogger) SecRuleTriggered(request waf.HTTPRequest, stmt secrule.Statement, action string, msg string, logData string) {
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

	bb, err := json.Marshal(lg)
	if err != nil {
		l.logger.Error().Err(err).Msg("Error while marshaling JSON results log")
	}

	l.writelogline <- bb
	<-l.writeDone
}

func (l *filelogResultsLogger) FieldBytesLimitExceeded(request waf.HTTPRequest, limit int) {
	l.bytesLimitExceeded(request, fmt.Sprintf("Request body contained a field longer than the limit (%d bytes)", limit))
}

func (l *filelogResultsLogger) PausableBytesLimitExceeded(request waf.HTTPRequest, limit int) {
	l.bytesLimitExceeded(request, fmt.Sprintf("Request body length (excluding file upload fields) exceeded the limit (%d bytes)", limit))
}

func (l *filelogResultsLogger) TotalBytesLimitExceeded(request waf.HTTPRequest, limit int) {
	l.bytesLimitExceeded(request, fmt.Sprintf("Request body length exceeded the limit (%d bytes)", limit))
}

func (l *filelogResultsLogger) bytesLimitExceeded(request waf.HTTPRequest, msg string) {
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

	bb, err := json.Marshal(lg)
	if err != nil {
		l.logger.Error().Err(err).Msg("Error while marshaling JSON results log")
	}

	l.writelogline <- bb
	<-l.writeDone
}

func (l *filelogResultsLogger) BodyParseError(request waf.HTTPRequest, err error) {
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

	bb, err := json.Marshal(lg)
	if err != nil {
		l.logger.Error().Err(err).Msg("Error while marshaling JSON results log")
	}

	l.writelogline <- bb
	<-l.writeDone
}

func (l *filelogResultsLogger) SetLogMetaData(metaData waf.ConfigLogMetaData) {
	l.metaData = metaData
}
