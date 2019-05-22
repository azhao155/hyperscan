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
	siteName string
}

func (s *engineImpl) EvalRequest(req *pb.WafHttpRequest) bool {
	log.Print("SecRule engine got EvalRequest for " + s.siteName + " with URI " + req.Uri)
	return true
}
