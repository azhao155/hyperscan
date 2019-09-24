package waf

// ResultsLogger is where the WAF writes high level customer facing results.
type ResultsLogger interface {
	FieldBytesLimitExceeded(request ResultsLoggerHTTPRequest, limit int)
	PausableBytesLimitExceeded(request ResultsLoggerHTTPRequest, limit int)
	TotalBytesLimitExceeded(request ResultsLoggerHTTPRequest, limit int)
	BodyParseError(request ResultsLoggerHTTPRequest, err error)
	SetLogMetaData(data ConfigLogMetaData)
}

// ResultsLoggerHTTPRequest represents an HTTP request to be logged by ResultsLogger.
type ResultsLoggerHTTPRequest interface {
	ConfigID() string
	URI() string
	LogMetaData() RequestLogMetaData
	TransactionID() string
}
