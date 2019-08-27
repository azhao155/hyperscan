package secrule

import (
	"azwaf/waf"
	"github.com/rs/zerolog"
)

type engineImpl struct {
	statements       []Statement
	reqScanner       ReqScanner
	scratchSpaceNext chan *ReqScannerScratchSpace
	ruleEvaluator    RuleEvaluator
	resultsLogger    ResultsLogger
}

// NewEngine creates a SecRule engine from statements
func NewEngine(statements []Statement, rsf ReqScannerFactory, re RuleEvaluator, rl ResultsLogger) (engine waf.SecRuleEngine, err error) {
	rs, err := rsf.NewReqScanner(statements)
	if err != nil {
		return
	}

	engine = &engineImpl{
		statements:    statements,
		reqScanner:    rs,
		ruleEvaluator: re,
		resultsLogger: rl,
	}
	return
}

type secRuleEvaluationImpl struct {
	logger               zerolog.Logger
	engine               *engineImpl
	request              waf.HTTPRequest
	scanResults          *ScanResults
	ruleTriggeredCb      func(stmt Statement, isDisruptive bool, msg string, logData string)
	reqScannerEvaluation ReqScannerEvaluation
	scratchSpaceNext     chan *ReqScannerScratchSpace
	scratchSpace         *ReqScannerScratchSpace
}

func (s *engineImpl) NewEvaluation(logger zerolog.Logger, req waf.HTTPRequest) waf.SecRuleEvaluation {
	ruleTriggeredCb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		action := "Matched"
		if isDisruptive {
			action = "Blocked"
		}

		s.resultsLogger.SecRuleTriggered(req, stmt, action, msg, logData)
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
		logger:               logger,
		engine:               s,
		ruleTriggeredCb:      ruleTriggeredCb,
		reqScannerEvaluation: reqScannerEvaluation,
		scratchSpaceNext:     s.scratchSpaceNext,
		scratchSpace:         scratchSpace,
	}
}

func (s *secRuleEvaluationImpl) ScanHeaders() (err error) {
	s.scanResults, err = s.reqScannerEvaluation.ScanHeaders(s.request)
	return
}

func (s *secRuleEvaluationImpl) ScanBodyField(contentType waf.ContentType, fieldName string, data string) (err error) {
	return s.reqScannerEvaluation.ScanBodyField(contentType, fieldName, data, s.scanResults)
}

func (s *secRuleEvaluationImpl) EvalRules() bool {
	if s.logger.Debug() != nil {
		for key, match := range s.scanResults.rxMatches {
			s.logger.Debug().
				Int("ruleID", key.ruleID).
				Int("ruleItemIdx", key.ruleItemIdx).
				Str("target", key.target).
				Str("matchedData", string(match.Data)).
				Msg("Request scanning found a match")
		}
	}

	// TODO: populate initial values as part of TxState task
	perRequestEnv := newEnvMap()

	allow, statusCode, err := s.engine.ruleEvaluator.Process(s.logger, perRequestEnv, s.engine.statements, s.scanResults, s.ruleTriggeredCb)
	if err != nil {
		s.logger.Debug().Err(err).Msg("SecRule engine got rule evaluation error")
		return false
	}

	s.logger.Debug().Bool("allow", allow).Int("statusCode", statusCode).Msg("SecRule engine rule evaluation decision")

	// TODO return status code
	if !allow {
		return false
	}

	return true
}

// Release resources.
func (s *secRuleEvaluationImpl) Close() {
	s.scratchSpaceNext <- s.scratchSpace
}
