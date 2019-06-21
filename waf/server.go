package waf

import (
	"azwaf/config"
	pb "azwaf/proto"
	"azwaf/secrule"
	"fmt"
)

// Server is the top level interface to AzWaf.
type Server interface {
	EvalRequest(*pb.WafHttpRequest) (*pb.WafDecision, error)
}

type serverImpl struct {
	secRuleEngines map[string]secrule.Engine
}

// NewServer creates a new top level AzWaf.
func NewServer(c *config.Main, sref secrule.EngineFactory) (server Server, err error) {
	s := &serverImpl{}

	s.secRuleEngines = make(map[string]secrule.Engine)

	for i, site := range c.Sites {
		var engine secrule.Engine
		engine, err = sref.NewEngine(secrule.RuleSetID(site.RuleSet))
		if err != nil {
			err = fmt.Errorf("failed to create SecRule engine for site %v: %v", site.Name, err)
			return
		}

		name := c.Sites[i].Name
		s.secRuleEngines[name] = engine
	}

	server = s
	return
}

func (s *serverImpl) EvalRequest(req *pb.WafHttpRequest) (*pb.WafDecision, error) {
	// TODO Decide which site this request belongs to.
	site := "site1"

	s.secRuleEngines[site].EvalRequest(req)

	return &pb.WafDecision{Allow: true}, nil
}
