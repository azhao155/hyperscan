package waf

// ResultsLogger is where the WAF writes high level customer facing results.
type ResultsLogger interface {
	FieldBytesLimitExceeded(request HTTPRequest, limit int)
	PausableBytesLimitExceeded(request HTTPRequest, limit int)
	TotalBytesLimitExceeded(request HTTPRequest, limit int)
	BodyParseError(request HTTPRequest, err error)
}
