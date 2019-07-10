package secrule

import (
	"azwaf/waf"
	log "github.com/sirupsen/logrus"
	"time"
)

type engineImpl struct {
	rules         []Rule
	reqScanner    ReqScanner
	ruleEvaluator RuleEvaluator
}

func (s *engineImpl) EvalRequest(req waf.HTTPRequest) bool {
	log.WithFields(log.Fields{"URI": req.URI()}).Info("SecRule engine got EvalRequest")
	startTime := time.Now()
	defer func() {
		log.WithFields(log.Fields{"timeTaken": time.Since(startTime)}).Info("SecRule EvalRequest done")
	}()

	scanResults, err := s.reqScanner.Scan(req)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("SecRule engine got scanning error")
		return false
	}

	for key, match := range scanResults.rxMatches {
		lf := log.Fields{"ruleID": key.ruleID, "ruleItemIdx": key.ruleItemIdx, "target": key.target, "matchedData": string(match.Data)}
		log.WithFields(lf).Debug("Request scanning found a match")
	}

	allow, statusCode, err := s.ruleEvaluator.Process(s.rules, scanResults)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("SecRule engine got rule evaluation error")
		return false
	}

	log.WithFields(log.Fields{"allow": allow, "statusCode": statusCode}).Debug("SecRule engine rule evaluation decision")

	// TODO return status code
	if !allow {
		return false
	}

	return true
}
