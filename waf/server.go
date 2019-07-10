package waf

import (
	"azwaf/config"
	"fmt"
)

// Server is the top level interface to AzWaf.
type Server interface {
	EvalRequest(HTTPRequest) (allow bool, err error)
}

type serverImpl struct {
	secRuleEngines map[string]SecRuleEngine
}

// NewServer creates a new top level AzWaf.
func NewServer(c *config.Main, sref SecRuleEngineFactory) (server Server, err error) {
	s := &serverImpl{}

	s.secRuleEngines = make(map[string]SecRuleEngine)

	for i, site := range c.Sites {
		var engine SecRuleEngine
		engine, err = sref.NewEngine(RuleSetID(site.RuleSet))
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

func (s *serverImpl) EvalRequest(req HTTPRequest) (allow bool, err error) {
	// TODO Decide which site this request belongs to.
	site := "site1"
	allow = s.secRuleEngines[site].EvalRequest(req)
	return
}
