package waf

import (
	"fmt"
	"sort"
	"time"

	"github.com/rs/zerolog"
)

type engineInstances struct {
	sre SecRuleEngine
	cre CustomRuleEngine
}

// Server is the top level interface to AzWaf.
type Server interface {
	EvalRequest(HTTPRequest) (allow bool, err error)
	PutConfig(Config) error
	DisposeConfig(int) error
}

type serverImpl struct {
	logger                  zerolog.Logger
	configMgr               ConfigMgr
	engines                 map[string]engineInstances
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

	s.engines = make(map[string]engineInstances)

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
		engines:           make(map[string]engineInstances),
	}
	s.engines[""] = engineInstances{
		sre: sre,
	}
	server = s

	return
}

func (s *serverImpl) EvalRequest(req HTTPRequest) (allow bool, err error) {
	// Create a sub-logger with a transaction ID
	logger := s.logger.With().Str("txid", req.TransactionID()).Logger()

	if logger.Info() != nil {
		logger.Info().Str("uri", req.URI()).Msg("WAF got request")
		startTime := time.Now()
		defer func() {
			logger.Info().Dur("timeTaken", time.Since(startTime)).Str("uri", req.URI()).Bool("allow", allow).Msg("WAF completed request")
		}()
	}

	configID := req.ConfigID()

	// TODO Also need to check id in other Engine map, if id not in any engine map, return error
	engines, idExists := s.engines[configID]
	if !idExists {
		err = fmt.Errorf("request specified an unknown ConfigID: %v", configID)
		return
	}

	secRuleEvaluation := engines.sre.NewEvaluation(logger, req)
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
		engines := engineInstances{}
		configID := config.ConfigID()

		// Create SecRuleEngine.
		if secRuleConfig := config.SecRuleConfig(); secRuleConfig != nil {
			var sre SecRuleEngine
			sre, err = s.secRuleEngineFactory.NewEngine(secRuleConfig)
			if err != nil {
				err = fmt.Errorf("failed to create SecRule engine for configID %v: %v", configID, err)
				return
			}
			engines.sre = sre
		}

		// Create CustomRuleEngine.
		if customRuleConfig := config.CustomRuleConfig(); customRuleConfig != nil {
			var cre CustomRuleEngine
			cre, err = s.customRuleEngineFactory.NewEngine(customRuleConfig)
			if err != nil {
				err = fmt.Errorf("failed to create CustomRule engine for configID %v: %v", configID, err)
				return
			}
			engines.cre = cre
		}

		s.engines[configID] = engines
	}

	s.resultsLogger.SetLogMetaData(c.LogMetaData())
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
		_, idExists := s.engines[id]
		// TODO Also need to check id in other Engine map,
		// if id not in any engine map, return error

		if !idExists {
			return fmt.Errorf("configID %v not valid, can't delete", id)
		}

		delete(s.engines, id)

		// TODO add other engine
	}

	return nil
}
