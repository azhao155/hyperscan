package secrule

import (
	"azwaf/waf"
	"log"
)

type engineImpl struct {
	rules         []Rule
	reqScanner    ReqScanner
	ruleEvaluator RuleEvaluator
}

func (s *engineImpl) EvalRequest(req waf.HTTPRequest) bool {
	log.Print("SecRule engine got EvalRequest for with URI " + req.URI())
	scanResults, err := s.reqScanner.Scan(req)
	if err != nil {
		log.Printf("Error while scanning request: %v", err)
		return false
	}

	for key, match := range scanResults.rxMatches {
		log.Printf("rxMatch. RuleID: %d. Target: %v. Data: \"%v\".", key.ruleID, key.target, string(match.Data))
	}

	allow, statusCode, err := s.ruleEvaluator.Process(s.rules, scanResults)
	if err != nil {
		log.Printf("Error while evaluating request: %v", err)
		return false
	}

	//TODO: return status code
	if !allow {
		log.Printf("Rejecting request with status code %d", statusCode)
		return false
	}

	return true
}
