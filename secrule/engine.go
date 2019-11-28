package secrule

import (
	"azwaf/waf"

	"github.com/rs/zerolog"
)

type engineImpl struct {
	statements             []Statement
	reqScanner             ReqScanner
	scratchSpaceNext       chan *ReqScannerScratchSpace
	ruleEvaluator          RuleEvaluator
	usesFullRawRequestBody bool
	ruleSetID              waf.RuleSetID
}

// NewEngine creates a SecRule engine from statements
func NewEngine(statements []Statement, rsf ReqScannerFactory, re RuleEvaluator, ruleSetID waf.RuleSetID) (engine waf.SecRuleEngine, err error) {
	reqScanner, err := rsf.NewReqScanner(statements)
	if err != nil {
		return
	}

	// Buffered channel used for reuse of scratch spaces between requests, while not letting concurrent requests share the same scratch space.
	scratchSpaceNext := make(chan *ReqScannerScratchSpace, 100000)
	s, err := reqScanner.NewScratchSpace()
	if err != nil {
		panic(err)
	}
	scratchSpaceNext <- s

	usesFullRawRequestBody := usesRequestBodyTarget(statements)

	engine = &engineImpl{
		statements:             statements,
		reqScanner:             reqScanner,
		ruleEvaluator:          re,
		scratchSpaceNext:       scratchSpaceNext,
		usesFullRawRequestBody: usesFullRawRequestBody,
		ruleSetID:              ruleSetID,
	}

	return
}

type secRuleEvaluationImpl struct {
	logger               zerolog.Logger
	resultsLogger        waf.SecRuleResultsLogger
	engine               *engineImpl
	request              waf.HTTPRequest
	scanResults          *ScanResults
	ruleTriggeredCb      func(stmt Statement, isDisruptive bool, msg string, logData string)
	reqScannerEvaluation ReqScannerEvaluation
	scratchSpaceNext     chan *ReqScannerScratchSpace
	scratchSpace         *ReqScannerScratchSpace
}

func (s *engineImpl) NewEvaluation(logger zerolog.Logger, resultsLogger waf.SecRuleResultsLogger, req waf.HTTPRequest) waf.SecRuleEvaluation {
	ruleTriggeredCb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		action := "Matched"
		if isDisruptive {
			action = "Blocked"
		}

		var ruleID int
		switch stmt := stmt.(type) {
		case *Rule:
			ruleID = stmt.ID
		case *ActionStmt:
			ruleID = stmt.ID
		}

		// ModSec truncates these fields to 512 bytes, so we will too.
		if len(msg) > 512 {
			msg = msg[:512-3] + "..."
		}
		if len(logData) > 512 {
			logData = logData[:512-3] + "..."
		}

		logger.Info().Int("ruleID", ruleID).Str("action", action).Str("msg", msg).Str("logData", logData).Msg("SecRule triggered")

		resultsLogger.SecRuleTriggered(ruleID, action, msg, logData, s.ruleSetID)
	}

	// Reuse a scratch space, or create a new one if there are none available
	var scratchSpace *ReqScannerScratchSpace
	if len(s.scratchSpaceNext) > 0 {
		scratchSpace = <-s.scratchSpaceNext
	} else {
		var err error
		scratchSpace, err = s.reqScanner.NewScratchSpace()
		if err != nil {
			panic(err)
		}
	}

	reqScannerEvaluation := s.reqScanner.NewReqScannerEvaluation(scratchSpace)

	return &secRuleEvaluationImpl{
		request:              req,
		resultsLogger:        resultsLogger,
		logger:               logger,
		engine:               s,
		ruleTriggeredCb:      ruleTriggeredCb,
		reqScannerEvaluation: reqScannerEvaluation,
		scratchSpaceNext:     s.scratchSpaceNext,
		scratchSpace:         scratchSpace,
	}
}

func (s *engineImpl) UsesFullRawRequestBody() bool {
	return s.usesFullRawRequestBody
}

func (s *secRuleEvaluationImpl) ScanHeaders() (err error) {
	s.scanResults, err = s.reqScannerEvaluation.ScanHeaders(s.request)
	return
}

func (s *secRuleEvaluationImpl) ScanBodyField(contentType waf.ContentType, fieldName string, data string) (err error) {
	return s.reqScannerEvaluation.ScanBodyField(contentType, fieldName, data, s.scanResults)
}

func (s *secRuleEvaluationImpl) EvalRules() (wafDecision waf.Decision) {
	if s.logger.Debug() != nil {
		for key, matches := range s.scanResults.matches {
			for _, match := range matches {
				s.logger.Debug().
					Int("ruleID", key.ruleID).
					Int("ruleItemIdx", key.ruleItemIdx).
					Str("targetName", key.target.Name).
					Str("targetSelector", key.target.Selector).
					Str("matchedData", string(match.Data)).
					Msg("Request scanning found a match")
			}
		}
	}

	perRequestEnv := newEnvironment(s.scanResults)

	wafDecision, statusCode, err := s.engine.ruleEvaluator.Process(s.logger, perRequestEnv, s.engine.statements, s.scanResults, s.ruleTriggeredCb)
	if err != nil {
		s.logger.Debug().Err(err).Msg("SecRule engine got rule evaluation error")
		return
	}

	s.logger.Debug().Int("wafDecision", int(wafDecision)).Int("statusCode", statusCode).Msg("SecRule engine rule evaluation decision")

	// TODO return status code
	return
}

// Release resources.
func (s *secRuleEvaluationImpl) Close() {
	s.scratchSpaceNext <- s.scratchSpace
}

func usesRequestBodyTarget(statements []Statement) bool {
	for _, stmt := range statements {
		switch stmt := stmt.(type) {
		case *Rule:
			for _, ruleItem := range stmt.Items {
				for _, target := range ruleItem.Predicate.Targets {
					if target.Name == "REQUEST_BODY" {
						return true
					}
				}
			}
		}
	}

	return false
}
