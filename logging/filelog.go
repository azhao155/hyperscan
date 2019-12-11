package logging

import (
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

const retryOpenTimes = 20

type logFileWriter struct {
	fileSystem   LogFileSystem
	file         LogFile
	logger       zerolog.Logger
	writelogline chan []byte
	writeDone    chan bool
	reopenFileCh chan bool
}

func newLogFileWriter(fileSystem LogFileSystem, logger zerolog.Logger, reopenFileCh chan bool) (*logFileWriter, error) {
	r := &logFileWriter{fileSystem: fileSystem, logger: logger, reopenFileCh: reopenFileCh}

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
		for {
			select {
			case <-reopenFileCh:
				r.openFilewithRetry(fileSystem, logger)

			case bytes := <-r.writelogline:
				r.file.Append(bytes)
				r.file.Append([]byte("\n"))
				r.writeDone <- true
			}
		}
	}()

	return r, nil
}

func (l *logFileWriter) openFilewithRetry(fileSystem LogFileSystem, logger zerolog.Logger) {
	var err error
	l.file.Close()

	for i := 0; i < retryOpenTimes; i++ {
		l.file, err = fileSystem.Open(Path + FileName)
		if err != nil {
			logger.Error().Err(err).Str("file", Path+FileName).Msg("Failed to open the file during reopen")
			time.Sleep(1 * time.Second)
			continue
		}

		return
	}

	panic(fmt.Sprintf("Failed to reopen log file: %v after %v retries.", Path+FileName, retryOpenTimes))
}

func (l *logFileWriter) writeLogLine(data interface{}) {
	bb, err := json.Marshal(data)
	if err != nil {
		l.logger.Error().Err(err).Msg("Error while marshaling JSON results log")
	}

	l.writelogline <- bb
	<-l.writeDone
}

type fileLogResultsLoggerFactory struct {
	writer *logFileWriter
}

// NewFileLogResultsLoggerFactory creates a factory which can create result loggers that writes to files.
func NewFileLogResultsLoggerFactory(fileSystem LogFileSystem, logger zerolog.Logger, reopenFileCh chan bool) (resultsLoggerFactory waf.ResultsLoggerFactory, err error) {
	var writer *logFileWriter
	writer, err = newLogFileWriter(fileSystem, logger, reopenFileCh)
	if err != nil {
		return
	}

	resultsLoggerFactory = &fileLogResultsLoggerFactory{
		writer: writer,
	}

	return
}

// NewFileResultsLogger creates a results logger that write log messages to file.
func (f *fileLogResultsLoggerFactory) NewResultsLogger(request waf.HTTPRequest, configLogMetaData waf.ConfigLogMetaData, isDetectionMode bool) waf.ResultsLogger {
	l := &filelogResultsLogger{
		writer:          f.writer,
		triggerTime:     time.Now().UTC(),
		isDetectionMode: isDetectionMode,
		request:         request,
	}

	if configLogMetaData != nil {
		l.resourceID = configLogMetaData.ResourceID()
		l.instanceID = configLogMetaData.InstanceID()
	}

	if request.LogMetaData() != nil {
		l.policyScope = request.LogMetaData().Scope()
		l.policyScopeName = request.LogMetaData().ScopeName()
	}

	for _, h := range request.Headers() {
		if strings.EqualFold(h.Key(), "host") {
			l.hostHeader = h.Value()
			break
		}
	}

	return l
}

type filelogResultsLogger struct {
	writer          *logFileWriter
	request         waf.HTTPRequest
	triggerTime     time.Time
	isDetectionMode bool
	resourceID      string
	instanceID      string
	policyScope     string
	policyScopeName string
	hostHeader      string
}

type secRuleSetInfo struct {
	ruleSetType    string
	ruleSetVersion string
}

var secRuleSetInfos = map[waf.RuleSetID]secRuleSetInfo{
	"OWASP CRS 3.0": {"OWASP", "CRS 3.0"},
}

// SecRuleTriggered is to be called when a SecRule was triggered.
func (l *filelogResultsLogger) SecRuleTriggered(ruleID int, decision waf.Decision, msg string, logData string, ruleSetID waf.RuleSetID) {
	rsi := secRuleSetInfos[ruleSetID]

	var action string
	switch decision {
	case waf.Pass:
		action = "Matched"
	case waf.Block:
		if l.isDetectionMode {
			action = "Detected"
		} else {
			action = "Blocked"
		}
	case waf.Allow:
		if l.isDetectionMode {
			action = "Detected"
		} else {
			action = "Allowed"
		}
	}

	lg := &customerFirewallLogEntry{
		TimeStamp:     l.triggerTime.Format(azureLogDateFormat),
		ResourceID:    l.resourceID,
		OperationName: "ApplicationGatewayFirewall",
		Category:      "ApplicationGatewayFirewallLog",
		Properties: customerFirewallLogEntryProperty{
			InstanceID:     l.instanceID,
			ClientIP:       l.request.RemoteAddr(),
			RequestURI:     l.request.URI(),
			RuleID:         strconv.Itoa(ruleID),
			RuleGroup:      "", // TODO write rule group
			RuleSetType:    rsi.ruleSetType,
			RuleSetVersion: rsi.ruleSetVersion,
			Message:        msg,
			Action:         action,
			Details: customerFirewallLogDetailsEntry{
				Message: logData,
			},
			Hostname:        l.hostHeader,
			TransactionID:   l.request.TransactionID(),
			PolicyID:        l.request.ConfigID(),
			PolicyScope:     l.policyScope,
			PolicyScopeName: l.policyScopeName,
			Engine:          "Azwaf",
		},
	}

	l.writer.writeLogLine(lg)
}

// IPReputationTriggered is to be called when a the IP reputation engine resulted in a request being blocked.
func (l *filelogResultsLogger) IPReputationTriggered() {
	lg := &customerFirewallIPReputationLogEntry{
		TimeStamp:     l.triggerTime.Format(azureLogDateFormat),
		ResourceID:    l.resourceID,
		OperationName: "ApplicationGatewayFirewall",
		Category:      "ApplicationGatewayFirewallLog",
		Properties: customerFirewallIPReputationLogEntryProperty{
			InstanceID:      l.instanceID,
			ClientIP:        l.request.RemoteAddr(),
			RequestURI:      l.request.URI(),
			RuleSetType:     "MicrosoftBotProtection",
			Message:         "IPReputationTriggered",
			Action:          l.blockedOrDetectedActionString(),
			Hostname:        l.hostHeader,
			TransactionID:   l.request.TransactionID(),
			PolicyID:        l.request.ConfigID(),
			PolicyScope:     l.policyScope,
			PolicyScopeName: l.policyScopeName,
			Engine:          "Azwaf",
		},
	}

	l.writer.writeLogLine(lg)
}

// FieldBytesLimitExceeded is to be called when the request body contained a field longer than the limit.
func (l *filelogResultsLogger) FieldBytesLimitExceeded(limit int) {
	l.bytesLimitExceeded(fmt.Sprintf("Request body contained a field longer than the limit (%d bytes)", limit))
}

// PausableBytesLimitExceeded is to be called when the request body length (excluding file upload fields) exceeded the limit.
func (l *filelogResultsLogger) PausableBytesLimitExceeded(limit int) {
	l.bytesLimitExceeded(fmt.Sprintf("Request body length (excluding file upload fields) exceeded the limit (%d bytes)", limit))
}

// TotalBytesLimitExceeded is to be called when the request body length exceeded the limit.
func (l *filelogResultsLogger) TotalBytesLimitExceeded(limit int) {
	l.bytesLimitExceeded(fmt.Sprintf("Request body length exceeded the limit (%d bytes)", limit))
}

// TotalFullRawRequestBodyLimitExceeded is to be called when the request body length exceeded the limit while entire body was being scanned as a single field.
func (l *filelogResultsLogger) TotalFullRawRequestBodyLimitExceeded(limit int) {
	l.bytesLimitExceeded(fmt.Sprintf("Request body length exceeded the limit (%d bytes) while the WAF was scanning the entire request body as a single field. The OWASP Core Rule Set and possibly other SecRule-based rule sets require this scan when the request body content-type is set to application/x-www-form-urlencoded.", limit))
}

func (l *filelogResultsLogger) bytesLimitExceeded(msg string) {
	lg := &customerFirewallLimitExceedLogEntry{
		TimeStamp:     l.triggerTime.Format(azureLogDateFormat),
		ResourceID:    l.resourceID,
		OperationName: "ApplicationGatewayFirewall",
		Category:      "ApplicationGatewayFirewallLog",
		Properties: customerFirewallLimitExceedLogEntryProperty{
			InstanceID:      l.instanceID,
			ClientIP:        l.request.RemoteAddr(),
			RequestURI:      l.request.URI(),
			Message:         msg,
			Action:          l.blockedOrDetectedActionString(),
			Hostname:        l.hostHeader,
			TransactionID:   l.request.TransactionID(),
			PolicyID:        l.request.ConfigID(),
			PolicyScope:     l.policyScope,
			PolicyScopeName: l.policyScopeName,
			Engine:          "Azwaf",
		},
	}

	l.writer.writeLogLine(lg)
}

// BodyParseError is to be called when the request body parser hit an error causing the request to be blocked.
func (l *filelogResultsLogger) BodyParseError(err error) {
	lg := &customerFirewallBodyParseLogEntry{
		TimeStamp:     l.triggerTime.Format(azureLogDateFormat),
		ResourceID:    l.resourceID,
		OperationName: "ApplicationGatewayFirewall",
		Category:      "ApplicationGatewayFirewallLog",
		Properties: customerFirewallBodyParseLogEntryProperty{
			InstanceID:      l.instanceID,
			ClientIP:        l.request.RemoteAddr(),
			RequestURI:      l.request.URI(),
			Message:         fmt.Sprintf("Request body scanning error"),
			Action:          l.blockedOrDetectedActionString(),
			Hostname:        l.hostHeader,
			TransactionID:   l.request.TransactionID(),
			PolicyID:        l.request.ConfigID(),
			PolicyScope:     l.policyScope,
			PolicyScopeName: l.policyScopeName,
			Details: customerFirewallLogBodyParseDetailsEntry{
				Message: err.Error(),
			},
			Engine: "Azwaf",
		},
	}

	l.writer.writeLogLine(lg)
}

// CustomRuleTriggered is to be called when a custom rule was triggered.
func (l *filelogResultsLogger) CustomRuleTriggered(customRuleID string, action string, matchedConditions []waf.ResultsLoggerCustomRulesMatchedConditions) {
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

	lg := &customerFirewallCustomRuleLogEntry{
		TimeStamp:     l.triggerTime.Format(azureLogDateFormat),
		ResourceID:    l.resourceID,
		OperationName: "ApplicationGatewayFirewall",
		Category:      "ApplicationGatewayFirewallLog",
		Properties: customerFirewallCustomRuleLogEntryProperties{
			InstanceID:      l.instanceID,
			ClientIP:        l.request.RemoteAddr(),
			RequestURI:      l.request.URI(),
			RuleSetType:     "Custom",
			RuleID:          customRuleID,
			Message:         message.String(),
			Action:          l.customRuleActionString(action),
			Hostname:        l.hostHeader,
			TransactionID:   l.request.TransactionID(),
			PolicyID:        l.request.ConfigID(),
			PolicyScope:     l.policyScope,
			PolicyScopeName: l.policyScopeName,
			Engine:          "Azwaf",
		},
	}

	l.writer.writeLogLine(lg)
}

func (l *filelogResultsLogger) customRuleActionString(customRuleAction string) string {
	switch customRuleAction {
	case "Block":
		if l.isDetectionMode {
			return "Detected"
		}
		return "Blocked"
	case "Allow":
		return "Allowed"
	default:
		return customRuleAction
	}
}

func (l *filelogResultsLogger) blockedOrDetectedActionString() string {
	if l.isDetectionMode {
		return "Detected"
	}
	return "Blocked"
}
