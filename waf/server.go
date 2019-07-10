package waf

import "fmt"

// Server is the top level interface to AzWaf.
type Server interface {
	EvalRequest(HTTPRequest) (allow bool, err error)
	PutConfig(Config, int64) error
}

type serverImpl struct {
	secRuleEngines map[int64]map[string]SecRuleEngine
	factory        SecRuleEngineFactory
}

// NewServer creates a new top level AzWaf.
func NewServer(c map[int64]Config, sref SecRuleEngineFactory) (server Server, err error) {
	s := &serverImpl{}

	s.factory = sref
	s.secRuleEngines = make(map[int64]map[string]SecRuleEngine)

	for i, config := range c {
		err = s.PutConfig(config, i)

		if err != nil {
			return
		}
	}

	server = s
	return
}

func (s *serverImpl) EvalRequest(req HTTPRequest) (allow bool, err error) {
	// TODO Decide which site this request belongs to. version and id will be contained in the req and configured by nginx
	if _, ok := s.secRuleEngines[req.Version()]; !ok {
		err = fmt.Errorf("Not found config for the request, version %v", req.Version())
		return
	}

	if _, ok := s.secRuleEngines[req.Version()][req.SecRuleID()]; !ok {
		err = fmt.Errorf("Not found config for the request, version %v seculeID %v", req.Version(), req.SecRuleID())
		return
	}

	// TODO add other engine

	allow = s.secRuleEngines[req.Version()][req.SecRuleID()].EvalRequest(req)

	return
}

func (s *serverImpl) PutConfig(c Config, v int64) (err error) {
	if _, ok := s.secRuleEngines[v]; ok {
		err = fmt.Errorf("has conflict config, version %v", v)
		return
	}

	s.secRuleEngines[v] = make(map[string]SecRuleEngine)
	for _, secRuleConfig := range c.SecRuleConfigs() {
		var engine SecRuleEngine
		engine, err = s.factory.NewEngine(secRuleConfig)

		if err != nil {
			err = fmt.Errorf("failed to create SecRule engine for version %v, id %v : %v", v, secRuleConfig.ID(), err)
			return
		}

		configID := secRuleConfig.ID()
		s.secRuleEngines[v][configID] = engine
	}

	// TODO add other engine

	return
}
