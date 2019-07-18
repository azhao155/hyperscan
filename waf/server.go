package waf

import (
	"fmt"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"time"
)

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
	if zerolog.GlobalLevel() >= zerolog.InfoLevel {
		log.Info().Str("uri", req.URI()).Msg("WAF got request")
		startTime := time.Now()
		defer func() {
			log.Info().Dur("timeTaken", time.Since(startTime)).Str("uri", req.URI()).Bool("allow", allow).Msg("WAF completed request")
		}()
	}

	version := req.Version()
	ruleSetID := req.RuleSetID()

	// TODO Decide which site this request belongs to. version and id will be contained in the req and configured by nginx
	if _, ok := s.secRuleEngines[version]; !ok {
		err = fmt.Errorf("not found config for the request, version %v", version)
		return
	}

	if _, ok := s.secRuleEngines[version][ruleSetID]; !ok {
		err = fmt.Errorf("not found config for the request, version %v ruleSetID %v", version, ruleSetID)
		return
	}

	// TODO add other engine

	allow = s.secRuleEngines[version][ruleSetID].EvalRequest(req)

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
