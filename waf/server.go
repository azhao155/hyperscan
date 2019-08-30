package waf

import (
	"fmt"
	"math/rand"
	"sort"
	"time"

	"github.com/rs/zerolog"
)

// Server is the top level interface to AzWaf.
type Server interface {
	EvalRequest(HTTPRequest) (allow bool, err error)
	PutConfig(Config) error
	DisposeConfig(int) error
}

type serverImpl struct {
	logger                  zerolog.Logger
	configMgr               ConfigMgr
	secRuleEngines          map[string]SecRuleEngine
	secRuleEngineFactory    SecRuleEngineFactory
	requestBodyParser       RequestBodyParser
	resultsLogger           ResultsLogger
	customRuleEngineFactory CustomRuleEngineFactory
}

// NewServer creates a new top level AzWaf.
func NewServer(logger zerolog.Logger, cm ConfigMgr, c map[int]Config, sref SecRuleEngineFactory, rbp RequestBodyParser, rl ResultsLogger, cref CustomRuleEngineFactory) (server Server, err error) {
	s := &serverImpl{
		logger:                  logger,
		configMgr:               cm,
		secRuleEngineFactory:    sref,
		requestBodyParser:       rbp,
		resultsLogger:           rl,
		customRuleEngineFactory: cref,
	}

	s.secRuleEngines = make(map[string]SecRuleEngine)

	var versions []int
	for v := range c {
		versions = append(versions, v)
	}
	sort.Ints(versions)

	for _, v := range versions {
		config := c[v]
		err = s.PutConfig(config)

		if err != nil {
			return
		}
	}

	server = s

	return
}

// NewStandaloneSecruleServer creates a new Azwaf server that only has a SecRule engine.
func NewStandaloneSecruleServer(logger zerolog.Logger, sre SecRuleEngine, rbp RequestBodyParser, rl ResultsLogger) (server Server, err error) {
	s := &serverImpl{
		logger:            logger,
		requestBodyParser: rbp,
		resultsLogger:     rl,
		secRuleEngines:    make(map[string]SecRuleEngine),
	}
	s.secRuleEngines[""] = sre
	server = s

	return
}

func (s *serverImpl) EvalRequest(req HTTPRequest) (allow bool, err error) {
	// Create a sub-logger with a transaction ID
	txid := fmt.Sprintf("%X", rand.Int())[:7] // TODO pass a txid down with the request from Nginx
	logger := s.logger.With().Str("txid", txid).Logger()

	if logger.Info() != nil {
		logger.Info().Str("uri", req.URI()).Msg("WAF got request")
		startTime := time.Now()
		defer func() {
			logger.Info().Dur("timeTaken", time.Since(startTime)).Str("uri", req.URI()).Bool("allow", allow).Msg("WAF completed request")
		}()
	}

	configID := req.ConfigID()

	// TODO Also need to check id in other Engine map, if id not in any engine map, return error
	_, secRuleOk := s.secRuleEngines[configID]
	if !secRuleOk {
		err = fmt.Errorf("request specified an unknown ConfigID: %v", configID)
		return
	}

	secRuleEvaluation := s.secRuleEngines[configID].NewEvaluation(logger, req)
	defer secRuleEvaluation.Close()

	err = secRuleEvaluation.ScanHeaders()
	if err != nil {
		return
	}

	err = s.requestBodyParser.Parse(logger, req, func(contentType ContentType, fieldName string, data string) (err error) {
		err = secRuleEvaluation.ScanBodyField(contentType, fieldName, data)
		// TODO add other engines who also need to do body scanning here
		return
	})
	if err != nil {
		lengthLimits := s.requestBodyParser.LengthLimits()
		if err == ErrFieldBytesLimitExceeded {
			s.resultsLogger.FieldBytesLimitExceeded(req, lengthLimits.MaxLengthField)
		} else if err == ErrPausableBytesLimitExceeded {
			s.resultsLogger.PausableBytesLimitExceeded(req, lengthLimits.MaxLengthPausable)
		} else if err == ErrTotalBytesLimitExceeded {
			s.resultsLogger.TotalBytesLimitExceeded(req, lengthLimits.MaxLengthTotal)
		} else {
			s.resultsLogger.BodyParseError(req, err)
		}

		allow = false
		return
	}

	allow = secRuleEvaluation.EvalRules()

	return
}

func (s *serverImpl) PutConfig(c Config) (err error) {
	err = s.configMgr.PutConfig(c)
	if err != nil {
		return
	}

	for _, config := range c.PolicyConfigs() {
		// Create SecRuleEngine map
		var engine SecRuleEngine
		secRuleConfig := config.SecRuleConfig()

		if secRuleConfig == nil {
			continue
		}

		engine, err = s.secRuleEngineFactory.NewEngine(secRuleConfig)

		if err != nil {
			err = fmt.Errorf("failed to create SecRule engine for configID %v: %v", config.ConfigID(), err)
			return
		}

		configID := config.ConfigID()

		s.secRuleEngines[configID] = engine

		// TODO add other engine
	}

	return
}

func (s *serverImpl) DisposeConfig(version int) (err error) {
	var ids []string
	if s.configMgr != nil {
		ids, err = s.configMgr.DisposeConfig(version)
		if err != nil {
			return
		}
	}

	for _, id := range ids {
		_, secRuleOk := s.secRuleEngines[id]
		// TODO Also need to check id in other Engine map,
		// if id not in any engine map, return error

		if !secRuleOk {
			return fmt.Errorf("configID %v not valid, can't delete", id)
		}

		if secRuleOk {
			delete(s.secRuleEngines, id)
		}

		// TODO add other engine
	}

	return nil
}
