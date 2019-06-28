package secrule

import (
	"azwaf/waf"
	"log"
)

type engineImpl struct {
	rules      []Rule
	reqScanner ReqScanner
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

	return true
}
