package waf

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

type engineInstances struct {
	sre        SecRuleEngine
	cre        CustomRuleEngine
	ireEnabled bool
}

// Server is the top level interface to AzWaf.
type Server interface {
	EvalRequest(HTTPRequest) (wafDecision Decision, err error)
	PutConfig(Config) error
	PutGeoIPData([]GeoIPDataRecord) error
	DisposeConfig(int) error
	PutIPReputationList([]string)
}

type serverImpl struct {
	logger                  zerolog.Logger
	configMgr               ConfigMgr
	engines                 map[string]engineInstances
	secRuleEngineFactory    SecRuleEngineFactory
	ipReputationEngine      IPReputationEngine
	requestBodyParser       RequestBodyParser
	resultsLogger           ResultsLogger
	customRuleEngineFactory CustomRuleEngineFactory
	geodb                   GeoDB
}

// NewServer creates a new top level AzWaf.
func NewServer(logger zerolog.Logger, cm ConfigMgr, c map[int]Config, sref SecRuleEngineFactory, rbp RequestBodyParser, rl ResultsLogger, cref CustomRuleEngineFactory, ire IPReputationEngine) (server Server, err error) {
	s := &serverImpl{
		logger:                  logger,
		configMgr:               cm,
		secRuleEngineFactory:    sref,
		requestBodyParser:       rbp,
		resultsLogger:           rl,
		customRuleEngineFactory: cref,
		ipReputationEngine:      ire,
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

	s.engines = make(map[string]engineInstances)
	s.engines[""] = engineInstances{sre: sre}

	return
}

func (s *serverImpl) EvalRequest(req HTTPRequest) (decision Decision, err error) {
	// Create a sub-logger with a transaction ID
	logger := s.logger.With().Str("txid", req.TransactionID()).Logger()

	if logger.Info() != nil {
		logger.Info().Str("uri", req.URI()).Msg("WAF got request")
		startTime := time.Now()
		defer func() {
			logger.Info().Dur("timeTaken", time.Since(startTime)).Str("uri", req.URI()).Int("decision", int(decision)).Msg("WAF completed request")
		}()
	}

	decision = Block
	configID := req.ConfigID()

	// TODO Also need to check id in other Engine map, if id not in any engine map, return error
	engines, idExists := s.engines[configID]
	if !idExists {
		err = fmt.Errorf("request specified an unknown ConfigID: %v", configID)
		return
	}

	var customRuleEvaluation CustomRuleEvaluation
	if engines.cre != nil {
		customRuleEvaluation = engines.cre.NewEvaluation(logger, req)
		defer customRuleEvaluation.Close()

		err = customRuleEvaluation.ScanHeaders()
		if err != nil {
			return
		}
	}

	var secRuleEvaluation SecRuleEvaluation
	if engines.sre != nil {
		secRuleEvaluation = engines.sre.NewEvaluation(logger, req)
		defer secRuleEvaluation.Close()

		err = secRuleEvaluation.ScanHeaders()
		if err != nil {
			return
		}
	}

	err = s.requestBodyParser.Parse(logger, req, func(contentType ContentType, fieldName string, data string) (err error) {
		if customRuleEvaluation != nil {
			err = customRuleEvaluation.ScanBodyField(contentType, fieldName, data)
			if err != nil {
				return err
			}
		}

		if secRuleEvaluation != nil {
			err = secRuleEvaluation.ScanBodyField(contentType, fieldName, data)
		}
		return
	})
	if err != nil {
		lengthLimits := s.requestBodyParser.LengthLimits()
		if err == ErrFieldBytesLimitExceeded {
			logger.Info().Int("limit", lengthLimits.MaxLengthField).Msg("Request body contained a field longer than the limit")
			s.resultsLogger.FieldBytesLimitExceeded(req, lengthLimits.MaxLengthField)
		} else if err == ErrPausableBytesLimitExceeded {
			logger.Info().Int("limit", lengthLimits.MaxLengthPausable).Msg("Request body length (excluding file upload fields) exceeded the limit")
			s.resultsLogger.PausableBytesLimitExceeded(req, lengthLimits.MaxLengthPausable)
		} else if err == ErrTotalBytesLimitExceeded {
			logger.Info().Int("limit", lengthLimits.MaxLengthTotal).Msg("Request body length exceeded the limit")
			s.resultsLogger.TotalBytesLimitExceeded(req, lengthLimits.MaxLengthTotal)
		} else {
			logger.Info().Err(err).Msg("Request body scanning error")
			s.resultsLogger.BodyParseError(req, err)
		}

		decision = Block
		return
	}

	// Custom rule evaluation always occurs first
	if customRuleEvaluation != nil {
		decision = customRuleEvaluation.EvalRules()
		if decision == Allow || decision == Block {
			return
		}
	}

	if engines.ireEnabled {
		decision = s.ipReputationEngine.EvalRequest(req)
		if decision == Allow || decision == Block {
			return
		}
	}

	if secRuleEvaluation != nil {
		decision = secRuleEvaluation.EvalRules()
	}

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
		if secRuleConfig := config.SecRuleConfig(); secRuleConfig != nil && secRuleConfig.Enabled() {
			var sre SecRuleEngine
			sre, err = s.secRuleEngineFactory.NewEngine(secRuleConfig)
			if err != nil {
				err = fmt.Errorf("failed to create SecRule engine for configID %v: %v", configID, err)
				return
			}
			engines.sre = sre
		}

		// Create CustomRuleEngine.
		if customRuleConfig := config.CustomRuleConfig(); customRuleConfig != nil && len(customRuleConfig.CustomRules()) > 0 {
			var cre CustomRuleEngine
			cre, err = s.customRuleEngineFactory.NewEngine(customRuleConfig)
			if err != nil {
				err = fmt.Errorf("failed to create CustomRule engine for configID %v: %v", configID, err)
				return
			}
			engines.cre = cre
		}

		// Populate IpReputation Enabled
		if ipReputationConfig := config.IPReputationConfig(); ipReputationConfig != nil {
			engines.ireEnabled = ipReputationConfig.Enabled()
		}

		s.engines[configID] = engines
	}

	s.resultsLogger.SetLogMetaData(c.LogMetaData())
	return
}

func (s *serverImpl) PutGeoIPData(geoIPData []GeoIPDataRecord) (err error) {
	return s.geodb.PutGeoIPData(geoIPData)
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

func (s *serverImpl) PutIPReputationList(ips []string) {
	sanitizedIps := sanitizeIPList(ips)
	s.ipReputationEngine.PutIPReputationList(sanitizedIps)
}

// Strips out unnecessary data that isn't the IP
// Sample input line: 255.255.255.255/32=bot:1
func sanitizeIPList(input []string) (output []string) {
	output = make([]string, 0)
	for _, str := range input {
		split := strings.Split(str, "=")
		ip := split[0]
		_, _, err := net.ParseCIDR(ip)
		if err != nil && net.ParseIP(ip) == nil {
			continue
		}
		output = append(output, split[0])
	}
	return
}
