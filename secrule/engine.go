package secrule

import (
	pb "azwaf/proto"

	"log"
)

// Engine is a SecRule engine, compatible with a subset of the ModSecurity SecRule language.
type Engine interface {
	EvalRequest(req *pb.WafHttpRequest) bool
}

type engineImpl struct {
	rules      []Rule
	reqScanner ReqScanner
}

func (s *engineImpl) EvalRequest(req *pb.WafHttpRequest) bool {
	log.Print("SecRule engine got EvalRequest for with URI " + req.Uri)
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
