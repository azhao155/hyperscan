package secrule

import (
	"azwaf/waf"
	"log"
	"time"
)

type engineImpl struct {
	rules         []Rule
	reqScanner    ReqScanner
	ruleEvaluator RuleEvaluator
}

func (s *engineImpl) EvalRequest(req waf.HTTPRequest) bool {
	log.Print("SecRule engine got EvalRequest for with URI " + req.URI())
	startTime := time.Now()
	defer func() { log.Printf("EvalRequest done in %v", time.Since(startTime)) }()

	scanResults, err := s.reqScanner.Scan(req)
	if err != nil {
		log.Printf("error while scanning request: %v", err)
		return false
	}

	for key, match := range scanResults.rxMatches {
		log.Printf("request scanning found a match for rule ID %d:%d. Target: %v. Data: \"%v\".", key.ruleID, key.ruleItemIdx, key.target, string(match.Data))
	}

	allow, statusCode, err := s.ruleEvaluator.Process(s.rules, scanResults)
	if err != nil {
		log.Printf("error while evaluating request: %v", err)
		return false
	}

	// TODO return status code
	if !allow {
		log.Printf("rejecting request with status code %d", statusCode)
		return false
	}

	return true
}
