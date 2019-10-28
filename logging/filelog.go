package logging

import (
	"azwaf/customrule"
	"azwaf/ipreputation"
	"azwaf/secrule"
	"azwaf/waf"
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// Path is the azwaf log path
const Path = "/appgwroot/log/azwaf/"

// FileName is the azwaf log file name
const FileName = "waf_json.log"

const azureLogDateFormat = "2006-01-02T15:04:05-07:00"

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

	triggerTime := time.Now().UTC() // TODO when ResultsLogger is per request, get this from l

	lg := &customerFirewallLogEntry{
		TimeStamp:     triggerTime.Format(azureLogDateFormat),
		ResourceID:    rID,
		OperationName: "ApplicationGatewayFirewall",
		Category:      "ApplicationGatewayFirewallLog",
		Properties: customerFirewallLogEntryProperty{
			InstanceID: iID,
			RequestURI: request.URI(),
			RuleID:     strconv.Itoa(ruleID),
			Message:    msg,
			Action:     action, // TODO "Blocked/Detected" instead of "deny", and based on isDetectionMode
			Details: customerFirewallLogDetailsEntry{
				Message: logData,
			},
			TransactionID:   request.TransactionID(),
			PolicyID:        request.ConfigID(),
			PolicyScope:     policyScope,
			PolicyScopeName: policyScopeName,
		},
	}

	l.writeLogLine(lg)
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

	triggerTime := time.Now().UTC() // TODO when ResultsLogger is per request, get this from l

	lg := &customerFirewallIPReputationLogEntry{
		TimeStamp:     triggerTime.Format(azureLogDateFormat),
		ResourceID:    rID,
		OperationName: "ApplicationGatewayFirewall",
		Category:      "ApplicationGatewayFirewallLog",
		Properties: customerFirewallIPReputationLogEntryProperty{
			InstanceID:      iID,
			RequestURI:      request.URI(),
			Message:         "IPReputationTriggered",
			Action:          "Blocked", // TODO based on isDetectionMode
			TransactionID:   request.TransactionID(),
			PolicyID:        request.ConfigID(),
			PolicyScope:     policyScope,
			PolicyScopeName: policyScopeName,
		},
	}

	l.writeLogLine(lg)
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

// TotalFullRawRequestBodyLimitExceeded is to be called when the request body length exceeded the limit while entire body was being scanned as a single field.
func (l *FilelogResultsLogger) TotalFullRawRequestBodyLimitExceeded(request waf.ResultsLoggerHTTPRequest, limit int) {
	l.bytesLimitExceeded(request, fmt.Sprintf("Request body length exceeded the limit (%d bytes) while the WAF was scanning the entire request body as a single field. The OWASP Core Rule Set and possibly other SecRule-based rule sets require this scan when the request body content-type is set to application/x-www-form-urlencoded.", limit))
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

	triggerTime := time.Now().UTC() // TODO when ResultsLogger is per request, get this from l

	lg := &customerFirewallLimitExceedLogEntry{
		TimeStamp:     triggerTime.Format(azureLogDateFormat),
		ResourceID:    rID,
		OperationName: "ApplicationGatewayFirewall",
		Category:      "ApplicationGatewayFirewallLog",
		Properties: customerFirewallLimitExceedLogEntryProperty{
			InstanceID:      iID,
			RequestURI:      request.URI(),
			Message:         msg,
			Action:          "Blocked", // TODO based on isDetectionMode
			TransactionID:   request.TransactionID(),
			PolicyID:        request.ConfigID(),
			PolicyScope:     policyScope,
			PolicyScopeName: policyScopeName,
		},
	}

	l.writeLogLine(lg)
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

	triggerTime := time.Now().UTC() // TODO when ResultsLogger is per request, get this from l

	lg := &customerFirewallBodyParseLogEntry{
		TimeStamp:     triggerTime.Format(azureLogDateFormat),
		ResourceID:    rID,
		OperationName: "ApplicationGatewayFirewall",
		Category:      "ApplicationGatewayFirewallLog",
		Properties: customerFirewallBodyParseLogEntryProperty{
			InstanceID:      iID,
			RequestURI:      request.URI(),
			Message:         fmt.Sprintf("Request body scanning error"),
			Action:          "Blocked", // TODO based on isDetectionMode
			TransactionID:   request.TransactionID(),
			PolicyID:        request.ConfigID(),
			PolicyScope:     policyScope,
			PolicyScopeName: policyScopeName,
			Details: customerFirewallLogBodyParseDetailsEntry{
				Message: err.Error(),
			},
		},
	}

	l.writeLogLine(lg)
}

// CustomRuleTriggered is to be called when a custom rule was triggered.
func (l *FilelogResultsLogger) CustomRuleTriggered(
	request customrule.ResultsLoggerHTTPRequest,
	rule waf.CustomRule,
	matchedConditions []customrule.ResultsLoggerMatchedConditions,
) {
	var resourceID string
	var instanceID string
	if l.metaData != nil {
		resourceID = l.metaData.ResourceID()
		instanceID = l.metaData.InstanceID()
	}

	var policyScope, policyScopeName string
	if request.LogMetaData() != nil {
		policyScope = request.LogMetaData().Scope()
		policyScopeName = request.LogMetaData().ScopeName()
	}

	var hostHeader string
	for _, h := range request.Headers() {
		if strings.EqualFold(h.Key(), "host") {
			hostHeader = h.Value()
		}
	}

	var message bytes.Buffer
	for _, rlmc := range matchedConditions {
		// Space after between each sentence.
		if message.Len() > 0 {
			message.WriteString(" ")
		}

		message.WriteString("Found condition ")
		message.WriteString(strconv.Itoa(rlmc.ConditionIndex))
		message.WriteString(" in ")
		message.WriteString(rlmc.VariableName)
		if rlmc.FieldName != "" {
			message.WriteString(", field name ")
			message.WriteString(rlmc.FieldName)
		}
		message.WriteString(", with value ")
		message.WriteString(rlmc.MatchedValue)
		message.WriteString(".")
	}

	action := customRuleActionString(rule.Action(), false) // TODO based on real isDetectionMode
	triggerTime := time.Now().UTC()                        // TODO when ResultsLogger is per request, get this from l

	lg := &customerFirewallCustomRuleLogEntry{
		TimeStamp:     triggerTime.Format(azureLogDateFormat),
		ResourceID:    resourceID,
		OperationName: "ApplicationGatewayFirewall",
		Category:      "ApplicationGatewayFirewallLog",
		Properties: customerFirewallCustomRuleLogEntryProperties{
			InstanceID:      instanceID,
			ClientIP:        request.RemoteAddr(),
			RequestURI:      request.URI(),
			RuleSetType:     "Custom",
			RuleID:          rule.Name(),
			Message:         message.String(),
			Action:          action,
			Hostname:        hostHeader,
			TransactionID:   request.TransactionID(),
			PolicyID:        request.ConfigID(),
			PolicyScope:     policyScope,
			PolicyScopeName: policyScopeName,
			Engine:          "Azwaf",
		},
	}

	l.writeLogLine(lg)
}

func (l *FilelogResultsLogger) writeLogLine(data interface{}) {
	bb, err := json.Marshal(data)
	if err != nil {
		l.logger.Error().Err(err).Msg("Error while marshaling JSON results log")
	}

	l.writelogline <- bb
	<-l.writeDone
}

// SetLogMetaData is to be called during initialization to set data needed by the logger later.
func (l *FilelogResultsLogger) SetLogMetaData(metaData waf.ConfigLogMetaData) {
	// Remove this function and let this data just be part of the normal PutConfig. More logical place, and easier for persistence between Azwaf restarts.
	l.metaData = metaData
}

func customRuleActionString(customRuleAction string, isDetectionMode bool) string {
	switch customRuleAction {
	case "Block":
		if isDetectionMode {
			return "Detected"
		}
		return "Blocked"
	case "Allow":
		return "Allowed"
	default:
		return customRuleAction
	}
}
