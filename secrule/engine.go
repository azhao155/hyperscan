package secrule

import (
	"azwaf/waf"
	"fmt"
	"github.com/rs/zerolog"
	"time"
)

type engineImpl struct {
	statements    []Statement
	reqScanner    ReqScanner
	ruleEvaluator RuleEvaluator
	resultsLogger ResultsLogger
}

func (s *engineImpl) EvalRequest(logger zerolog.Logger, req waf.HTTPRequest) bool {
	if logger.Info() != nil {
		logger.Info().Str("uri", req.URI()).Msg("SecRule engine got EvalRequest")
		startTime := time.Now()
		defer func() {
			logger.Info().Dur("timeTaken", time.Since(startTime)).Msg("SecRule EvalRequest done")
		}()
	}

	triggeredCb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		action := "Matched"
		if isDisruptive {
			action = "Blocked"
		}

		s.resultsLogger.SecRuleTriggered(req, stmt, action, msg, logData)
	}

	scanResults, err := s.reqScanner.Scan(req)
	if err != nil {
		lengthLimits := s.reqScanner.LengthLimits()
		if err == errFieldBytesLimitExceeded {
			triggeredCb(nil, true, fmt.Sprintf("Request body contained a field longer than the limit (%d bytes)", lengthLimits.MaxLengthField), "")
		} else if err == errPausableBytesLimitExceeded {
			triggeredCb(nil, true, fmt.Sprintf("Request body length (excluding file upload fields) exceeded the limit (%d bytes)", lengthLimits.MaxLengthPausable), "")
		} else if err == errTotalBytesLimitExceeded {
			triggeredCb(nil, true, fmt.Sprintf("Request body length exceeded the limit (%d bytes)", lengthLimits.MaxLengthTotal), "")
		} else {
			triggeredCb(nil, true, "Request body scanning error", err.Error())
		}

		return false
	}

	if logger.Debug() != nil {
		for key, match := range scanResults.rxMatches {
			logger.Debug().
				Int("ruleID", key.ruleID).
				Int("ruleItemIdx", key.ruleItemIdx).
				Str("target", key.target).
				Str("matchedData", string(match.Data)).
				Msg("Request scanning found a match")
		}
	}

	// TODO: populate initial values as part of TxState task
	perRequestEnv := newEnvMap()

	allow, statusCode, err := s.ruleEvaluator.Process(logger, perRequestEnv, s.statements, scanResults, triggeredCb)
	if err != nil {
		logger.Debug().Err(err).Msg("SecRule engine got rule evaluation error")
		return false
	}

	logger.Debug().Bool("allow", allow).Int("statusCode", statusCode).Msg("SecRule engine rule evaluation decision")

	// TODO return status code
	if !allow {
		return false
	}

	return true
}
