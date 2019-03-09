package waf

import (
	"azwaf/config"
	pb "azwaf/proto"
	"azwaf/secrule"
)

// Server is the top level interface to AzWaf.
type Server interface {
	EvalRequest(*pb.WafHttpRequest) (*pb.WafDecision, error)
}

type serverImpl struct {
	secRuleEngines map[string]secrule.Engine
}

// NewServer creates a new top level AzWaf.
func NewServer(c *config.Main, sref secrule.EngineFactory) Server {
	s := &serverImpl{}

	s.secRuleEngines = make(map[string]secrule.Engine)

	for i := 0; i < len(c.Sites); i++ {
		name := c.Sites[i].Name
		engine := sref.NewEngine(name)
		s.secRuleEngines[name] = engine
	}

	return s
}

func (s *serverImpl) EvalRequest(req *pb.WafHttpRequest) (*pb.WafDecision, error) {
	// TODO Decide which site this request belongs to.
	site := "site1"

	s.secRuleEngines[site].EvalRequest(req)

	return &pb.WafDecision{Allow: true}, nil
}
