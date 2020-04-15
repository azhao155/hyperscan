package waf

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

type policy struct {
	sre               SecRuleEngine
	cre               CustomRuleEngine
	ireEnabled        bool
	isDetectionMode   bool
	isShadowMode      bool
	requestBodyCheck  bool
	requestBodyParser RequestBodyParser
	configLogMetaData ConfigLogMetaData
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
	logger                     zerolog.Logger
	configMgr                  ConfigMgr
	policies                   map[string]policy
	secRuleEngineFactory       SecRuleEngineFactory
	ipReputationEngine         IPReputationEngine
	requestBodyParserFactory   RequestBodyParserFactory
	resultsLoggerFactory       ResultsLoggerFactory
	shadowresultsLoggerFactory ResultsLoggerFactory
	customRuleEngineFactory    CustomRuleEngineFactory
	geodb                      GeoDB
}

// NewServer creates a new top level AzWaf.
func NewServer(logger zerolog.Logger, cm ConfigMgr, c map[int]Config, rlf ResultsLoggerFactory, srlf ResultsLoggerFactory, sref SecRuleEngineFactory, rbpf RequestBodyParserFactory, cref CustomRuleEngineFactory, ire IPReputationEngine, geoDB GeoDB) (server Server, err error) {
	s := &serverImpl{
		logger:                     logger,
		configMgr:                  cm,
		resultsLoggerFactory:       rlf,
		requestBodyParserFactory:   rbpf,
		shadowresultsLoggerFactory: srlf,
		secRuleEngineFactory:       sref,
		customRuleEngineFactory:    cref,
		ipReputationEngine:         ire,
		geodb:                      geoDB,
	}

	s.policies = make(map[string]policy)

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
func NewStandaloneSecruleServer(logger zerolog.Logger, rlf ResultsLoggerFactory, sre SecRuleEngine, rbp RequestBodyParser) (server Server, err error) {
	s := &serverImpl{
		logger:               logger,
		resultsLoggerFactory: rlf,
		policies:             make(map[string]policy),
	}
	s.policies[""] = policy{
		sre: sre,
	}
	server = s

	s.policies = make(map[string]policy)
	s.policies[""] = policy{sre: sre, requestBodyCheck: true, requestBodyParser: rbp}

	return
}

func (s *serverImpl) EvalRequest(req HTTPRequest) (decision Decision, err error) {
	// Create a sub-logger with a transaction ID
	logger := s.logger.With().Str("txid", req.TransactionID()).Logger()

	if logger.Info() != nil {
		logger.Info().Str("uri", req.URI()).Msg("WAF got request")
		startTime := time.Now()
		defer func() {
			d := strconv.Itoa(int(decision))
			switch decision {
			case Pass:
				d = "Pass"
			case Allow:
				d = "Allow"
			case Block:
				d = "Block"
			}

			logger.Info().Dur("timeTaken", time.Since(startTime)).Str("uri", req.URI()).Str("decision", d).Msg("WAF completed request")
		}()
	}

	decision = Pass
	secRuleDecision := Pass
	configID := req.ConfigID()

	// TODO Also need to check id in other Engine map, if id not in any engine map, return error
	policy, idExists := s.policies[configID]

	if !idExists {
		err = fmt.Errorf("request specified an unknown ConfigID: %v", configID)
		decision = Block
		return
	}

	defer func() {
		if policy.isDetectionMode || policy.isShadowMode {
			decision = Pass
			if err != nil {
				logger.Warn().Err(err).Msg("Throwing err as warning in detection/shadow mode")
			}
			err = nil
		}
	}()

	// Create results-logger with the data specific to this request
	var resultsLogger ResultsLogger
	if !policy.isShadowMode {
		resultsLogger = s.resultsLoggerFactory.NewResultsLogger(req, policy.configLogMetaData, policy.isDetectionMode)
	} else {
		resultsLogger = s.shadowresultsLoggerFactory.NewResultsLogger(req, policy.configLogMetaData, policy.isDetectionMode)
	}

	contentLength, reqBodyType, multipartBoundary, err := getLengthAndTypeFromHeaders(req)
	if err != nil {
		resultsLogger.HeaderParseError(err)
		decision = Block
		err = nil
		return
	}

	var customRuleEvaluation CustomRuleEvaluation
	if policy.cre != nil {
		customRuleEvaluation = policy.cre.NewEvaluation(logger, resultsLogger, req, reqBodyType)
		defer customRuleEvaluation.Close()

		err = customRuleEvaluation.ScanHeaders()
		if err != nil {
			resultsLogger.HeaderParseError(err)
			decision = Block
			err = nil
			return
		}
	}

	var secRuleEvaluation SecRuleEvaluation
	if policy.sre != nil {
		secRuleEvaluation = policy.sre.NewEvaluation(logger, resultsLogger, req, reqBodyType)
		defer secRuleEvaluation.Close()

		err = secRuleEvaluation.ScanHeaders()
		if err != nil {
			resultsLogger.HeaderParseError(err)
			secRuleDecision = Block
			err = nil
			secRuleEvaluation = nil
		}

		// SecRule-lang's phase 1 rule evaluation must be run before body scanning, because it may influence whether to run body scanning or not.
		if secRuleEvaluation != nil {
			secRuleDecision = secRuleEvaluation.EvalRulesPhase1()
		}
	}

	if policy.requestBodyCheck {
		var alsoScanFullRawRequestBody bool
		if secRuleEvaluation != nil && alsoScanFullRawRequestBody == false {
			alsoScanFullRawRequestBody = secRuleEvaluation.AlsoScanFullRawRequestBody()
		}
		if customRuleEvaluation != nil && alsoScanFullRawRequestBody == false {
			alsoScanFullRawRequestBody = customRuleEvaluation.AlsoScanFullRawRequestBody()
		}

		// The callback function the body parser will call each time it has found a body field.
		bodyFieldCb := func(contentType FieldContentType, fieldName string, data string) (err error) {
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
		}

		err = policy.requestBodyParser.Parse(logger, req.BodyReader(), bodyFieldCb, reqBodyType, contentLength, multipartBoundary, alsoScanFullRawRequestBody)
		if err != nil {
			decision = Block
			lengthLimits := policy.requestBodyParser.LengthLimits()
			defer func() {
				err = nil
			}()
			if err == ErrFieldBytesLimitExceeded {
				logger.Info().Int("limit", lengthLimits.MaxLengthField).Msg("Request body contained a field longer than the limit")
				resultsLogger.FieldBytesLimitExceeded(lengthLimits.MaxLengthField)
				return
			} else if err == ErrPausableBytesLimitExceeded {
				logger.Info().Int("limit", lengthLimits.MaxLengthPausable).Msg("Request body length (excluding file upload fields) exceeded the limit")
				resultsLogger.PausableBytesLimitExceeded(lengthLimits.MaxLengthPausable)
				return
			} else if err == ErrTotalBytesLimitExceeded {
				logger.Info().Int("limit", lengthLimits.MaxLengthTotal).Msg("Request body length exceeded the limit")
				resultsLogger.TotalBytesLimitExceeded(lengthLimits.MaxLengthTotal)
				return
			} else if err == ErrTotalFullRawRequestBodyExceeded {
				logger.Info().Int("limit", lengthLimits.MaxLengthTotalFullRawRequestBody).Msg("Request body length exceeded the limit while entire body was being scanned as a single field")
				resultsLogger.TotalFullRawRequestBodyLimitExceeded(lengthLimits.MaxLengthTotalFullRawRequestBody)
				return
			} else {
				secRuleEvaluation.BodyParseErrorOccurred()
				logger.Info().Err(err).Msg("Request body scanning error")
				resultsLogger.BodyParseError(err)
			}
		}
	}

	// Custom rule evaluation always occurs first
	if customRuleEvaluation != nil {
		decision = customRuleEvaluation.EvalRules()
		// Short-circuiting
		if decision == Allow || decision == Block {
			return
		}
	}

	if policy.ireEnabled {
		decision = s.ipReputationEngine.EvalRequest(req, resultsLogger)
		if decision == Allow || decision == Block {
			return
		}
	}

	if secRuleDecision == Allow || secRuleDecision == Block {
		decision = secRuleDecision
	} else {
		// Run SecRule-lang's phases 2 through 5. Phase 1 was already run prior to body scanning.
		if secRuleEvaluation != nil {
			decision = secRuleEvaluation.EvalRulesPhase2to5()
		}
	}

	return
}

func (s *serverImpl) PutConfig(c Config) (err error) {
	err = s.configMgr.PutConfig(c)
	if err != nil {
		return
	}

	for _, config := range c.PolicyConfigs() {
		p := policy{
			configLogMetaData: c.LogMetaData(),
		}
		configID := config.ConfigID()
		p.isDetectionMode = config.IsDetectionMode()
		p.isShadowMode = config.IsShadowMode()
		p.requestBodyCheck = config.RequestBodyCheck()

		// Temporary placeholder value to bypass length limit checks
		// TODO: update limits with config received from Tenant
		maxInt := 2147483647
		limits := LengthLimits{
			MaxLengthField:                   maxInt,
			MaxLengthPausable:                1024 * int(config.RequestBodySizeLimitInKb()),
			MaxLengthTotal:                   1024 * 1024 * int(config.FileUploadSizeLimitInMb()),
			MaxLengthTotalFullRawRequestBody: maxInt,
		}

		p.requestBodyParser = s.requestBodyParserFactory.NewRequestBodyParser(limits)

		// Create SecRuleEngine.
		if secRuleConfig := config.SecRuleConfig(); secRuleConfig != nil && secRuleConfig.Enabled() {
			var sre SecRuleEngine
			sre, err = s.secRuleEngineFactory.NewEngine(secRuleConfig)
			if err != nil {
				err = fmt.Errorf("failed to create SecRule engine for configID %v: %v", configID, err)
				return
			}
			p.sre = sre
		}

		// Create CustomRuleEngine.
		if customRuleConfig := config.CustomRuleConfig(); customRuleConfig != nil && len(customRuleConfig.CustomRules()) > 0 {
			var cre CustomRuleEngine
			cre, err = s.customRuleEngineFactory.NewEngine(customRuleConfig)
			if err != nil {
				err = fmt.Errorf("failed to create CustomRule engine for configID %v: %v", configID, err)
				return
			}
			p.cre = cre
		}

		// Populate IpReputation Enabled
		if ipReputationConfig := config.IPReputationConfig(); ipReputationConfig != nil {
			p.ireEnabled = ipReputationConfig.Enabled()
		}

		s.policies[configID] = p
	}

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
		_, idExists := s.policies[id]
		if !idExists {
			return fmt.Errorf("configID %v not valid, can't delete", id)
		}
		delete(s.policies, id)
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
