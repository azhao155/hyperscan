package main

import (
	"azwaf/bodyparsing"
	"azwaf/customrule"
	"azwaf/grpc"
	"azwaf/hyperscan"
	"azwaf/logging"
	"azwaf/secrule"
	"azwaf/waf"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

type mockSecRuleConfig struct{}

func (c *mockSecRuleConfig) ID() string        { return "default" }
func (c *mockSecRuleConfig) Enabled() bool     { return false }
func (c *mockSecRuleConfig) RuleSetID() string { return "default" }

type mockConfig struct{}

func (c *mockConfig) SecRuleConfigs() []waf.SecRuleConfig {
	return []waf.SecRuleConfig{&mockSecRuleConfig{}}
}

func (c *mockConfig) GeoDBConfigs() []waf.GeoDBConfig { return []waf.GeoDBConfig{} }

func (c *mockConfig) IPReputationConfigs() []waf.IPReputationConfig { return []waf.IPReputationConfig{} }

// Dependency injection composition root
func main() {
	lengthLimits := waf.LengthLimits{
		MaxLengthField:    1024 * 20,         // 20 KiB
		MaxLengthPausable: 1024 * 128,        // 128 KiB
		MaxLengthTotal:    1024 * 1024 * 700, // 700 MiB
	}

	logLevel := flag.String("loglevel", "error", "sets log level. Can be one of: debug, info, warn, error, fatal, panic.")
	profiling := flag.Bool("profiling", false, "whether to enable the :6060/debug/pprof/ endpoint")
	secruleconf := flag.String("secruleconf", "", "if set, use the given SecRule config file instead of using the ConfigMgr service")
	limitsArg := flag.String("bodylimits", "", fmt.Sprintf("if set, use these request body length limits. Unit is bytes. These are only enforced within around 8KiB precision, due to various default buffer sizes. This parameter takes three integer values: max length of any single field, max length of request bodies excluding file fields in multipart/form-data bodies, and max total request body length. Example (these are the defaults): -limits=%v,%v,%v ", lengthLimits.MaxLengthField, lengthLimits.MaxLengthPausable, lengthLimits.MaxLengthTotal))
	flag.Parse()

	if *profiling {
		go func() {
			http.ListenAndServe(":6060", nil)
		}()
	}

	loglevel, _ := zerolog.ParseLevel(*logLevel)
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).Level(loglevel).With().Timestamp().Caller().Logger()

	rand.Seed(time.Now().UnixNano())

	lengthLimits = parseLengthLimitsArgOrDefault(logger, limitsArg, lengthLimits)

	p := secrule.NewRuleParser()
	rlfs := secrule.NewRuleLoaderFileSystem()
	rl := secrule.NewCrsRuleLoader(p, rlfs)

	// TODO Implement config manager config restore and pass restored config to NewServer. Also pass the config mgr to the grpc NewServer
	var cm waf.ConfigMgr
	var c map[int]waf.Config
	if *secruleconf != "" {
		c = make(map[int]waf.Config)
		c[0] = &mockConfig{}
		rl = secrule.NewStandaloneRuleLoader(p, rlfs, *secruleconf)
	} else {
		var err error
		cm, c, err = waf.NewConfigMgr(&waf.ConfigFileSystemImpl{}, &grpc.ConfigConverterImpl{})
		if err != nil {
			logger.Fatal().Err(err).Msg("Error while creating config manager")
		}
	}

	hsfs := hyperscan.NewCacheFileSystem()
	hscache := hyperscan.NewDbCache(hsfs)
	mref := hyperscan.NewMultiRegexEngineFactory(hscache)
	rsf := secrule.NewReqScannerFactory(mref)
	re := secrule.NewRuleEvaluator()
	secruleResLog, wafResLog := logging.NewZerologResultsLogger(logger)
	sref := secrule.NewEngineFactory(logger, rl, rsf, re, secruleResLog)
	rbp := bodyparsing.NewRequestBodyParser(lengthLimits)
	crl:= customrule.NewCustomRuleLoader()
	cref := customrule.NewEngineFactory(logger, crl, rsf, re)

	w, err := waf.NewServer(logger, cm, c, sref, rbp, wafResLog, cref)
	if err != nil {
		logger.Fatal().Err(err).Msg("Error while creating service manager")
	}
	s := grpc.NewServer(logger, w)
	logger.Info().Msg("Starting WAF server")
	if err := s.Serve(); err != nil {
		logger.Fatal().Err(err).Msg("Error while running WAF server")
	}
}

func parseLengthLimitsArgOrDefault(logger zerolog.Logger, limitsArg *string, defaults waf.LengthLimits) (lengthLimits waf.LengthLimits) {
	lengthLimits = defaults

	if *limitsArg != "" {
		nn := strings.Split(*limitsArg, ",")
		if len(nn) != 3 {
			logger.Fatal().Msg("The limits arg must contain exactly 3 comma separated integer values")
		}

		n, err := strconv.Atoi(nn[0])
		if err != nil {
			logger.Fatal().Err(err).Msg("Error while parsing limits arg 1")
		}
		lengthLimits.MaxLengthField = n

		n, err = strconv.Atoi(nn[1])
		if err != nil {
			logger.Fatal().Err(err).Msg("Error while parsing limits arg 2")
		}
		lengthLimits.MaxLengthPausable = n

		n, err = strconv.Atoi(nn[2])
		if err != nil {
			logger.Fatal().Err(err).Msg("Error while parsing limits arg 3")
		}
		lengthLimits.MaxLengthTotal = n
	}

	return
}
