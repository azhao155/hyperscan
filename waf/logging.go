package waf

// ResultsLogger is where the WAF writes high level customer facing results.
type ResultsLogger interface {
	// Results that the top level WAF code may log
	FieldBytesLimitExceeded(limit int)
	PausableBytesLimitExceeded(limit int)
	TotalBytesLimitExceeded(limit int)
	TotalFullRawRequestBodyLimitExceeded(limit int)
	BodyParseError(err error)
	HeaderParseError(err error)

	// Results that the underlying engines may log
	SecRuleResultsLogger
	IPReputationResultsLogger
	CustomRuleResultsLogger
}

// ResultsLoggerFactory is a factory which can create result loggers.
type ResultsLoggerFactory interface {
	NewResultsLogger(request HTTPRequest, configLogMetaData ConfigLogMetaData, isDetectionMode bool) ResultsLogger
}
