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
}

type serverImpl struct {
	logger               zerolog.Logger
	secRuleEngines       map[string]SecRuleEngine
	secRuleEngineFactory SecRuleEngineFactory
	requestBodyParser    RequestBodyParser
	resultsLogger        ResultsLogger
}

// NewServer creates a new top level AzWaf.
func NewServer(logger zerolog.Logger, c map[int]Config, sref SecRuleEngineFactory, rbp RequestBodyParser, rl ResultsLogger) (server Server, err error) {
	s := &serverImpl{
		logger:               logger,
		secRuleEngineFactory: sref,
		requestBodyParser:    rbp,
		resultsLogger:        rl,
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

	secRuleConfigID := req.SecRuleConfigID()

	// TODO consider if this should be removed once config management is fully functional e2e
	if secRuleConfigID == "" {
		secRuleConfigID = "SecRuleConfig1"
	}

	if _, ok := s.secRuleEngines[secRuleConfigID]; !ok {
		err = fmt.Errorf("request specified an unknown secRuleConfigID: %v", secRuleConfigID)
		return
	}

	// TODO add other engine

	secRuleEvaluation := s.secRuleEngines[secRuleConfigID].NewEvaluation(logger, req)
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
	for _, secRuleConfig := range c.SecRuleConfigs() {
		var engine SecRuleEngine
		engine, err = s.secRuleEngineFactory.NewEngine(secRuleConfig)

		if err != nil {
			err = fmt.Errorf("failed to create SecRule engine for configID %v, error %v", secRuleConfig.ID(), err)
			return
		}

		configID := secRuleConfig.ID()

		s.secRuleEngines[configID] = engine
	}

	// TODO add other engine

	return
}
