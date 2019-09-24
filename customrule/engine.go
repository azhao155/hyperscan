package customrule

import (
	"azwaf/secrule"
	"azwaf/waf"

	"github.com/rs/zerolog"
)

type engineImpl struct {
	underlyingSecRuleEngine waf.SecRuleEngine
}

type customRuleEvaluationImpl struct {
	logger            zerolog.Logger
	request           waf.HTTPRequest
	secRuleEvaluation waf.SecRuleEvaluation
}

func (c *engineImpl) NewEvaluation(logger zerolog.Logger, req waf.HTTPRequest) waf.CustomRuleEvaluation {
	srev := c.underlyingSecRuleEngine.NewEvaluation(logger, req)

	return &customRuleEvaluationImpl{
		request:           req,
		logger:            logger,
		secRuleEvaluation: srev,
	}
}

func (c *customRuleEvaluationImpl) ScanHeaders() (err error) {
	err = c.secRuleEvaluation.ScanHeaders()
	return
}

func (c *customRuleEvaluationImpl) ScanBodyField(contentType waf.ContentType, fieldName string, data string) (err error) {
	return c.secRuleEvaluation.ScanBodyField(contentType, fieldName, data)
}

func (c *customRuleEvaluationImpl) EvalRules() (wafDecision waf.Decision) {
	return c.secRuleEvaluation.EvalRules()
}

func (c *customRuleEvaluationImpl) Close() {
	c.secRuleEvaluation.Close()
}

type secRuleEngineResultsLoggerAdapter struct {
	logger zerolog.Logger
}

func (l *secRuleEngineResultsLoggerAdapter) SecRuleTriggered(request secrule.ResultsLoggerHTTPRequest, stmt secrule.Statement, action string, msg string, logData string) {
	// TODO adapt the secrule results logger to a custom rules results logger in a way that makes sense (rule ids, line numbers, and file names, etc. don't really make sense here as they do in secrule results logs).
}
