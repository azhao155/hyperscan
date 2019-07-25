package main

import (
	"azwaf/grpc"
	"azwaf/hyperscan"
	"azwaf/logging"
	"azwaf/secrule"
	"azwaf/waf"
	"flag"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/rs/zerolog"
)

type mockSecRuleConfig struct{}

func (c *mockSecRuleConfig) ID() string        { return "SecRuleConfig1" }
func (c *mockSecRuleConfig) Enabled() bool     { return false }
func (c *mockSecRuleConfig) RuleSetID() string { return "OWASP CRS 3.0" }

type mockConfig struct{}

func (c *mockConfig) SecRuleConfigs() []waf.SecRuleConfig {
	return []waf.SecRuleConfig{&mockSecRuleConfig{}}
}

func (c *mockConfig) GeoDBConfigs() []waf.GeoDBConfig { return []waf.GeoDBConfig{} }

func (c *mockConfig) IPReputationConfigs() []waf.IPReputationConfig { return []waf.IPReputationConfig{} }

func main() {
	logLevel := flag.String("loglevel", "error", "sets log level. Can be one of: debug, info, warn, error, fatal, panic.")
	profiling := flag.Bool("profiling", false, "whether to enable the :6060/debug/pprof/ endpoint")
	var usedefaultwafconfig = flag.Bool("usedefaultwafconfig", false, "whether to use a default builtin WAF config instead of using ConfigMgr")
	flag.Parse()

	if *profiling {
		go func() {
			http.ListenAndServe(":6060", nil)
		}()
	}

	loglevel, _ := zerolog.ParseLevel(*logLevel)

	rand.Seed(time.Now().UnixNano())

	// Depedency injection composition root
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).Level(loglevel).With().Timestamp().Caller().Logger()
	p := secrule.NewRuleParser()
	rl := secrule.NewCrsRuleLoader(p)
	hsfs := hyperscan.NewCacheFileSystem()
	hscache := hyperscan.NewDbCache(hsfs)
	mref := hyperscan.NewMultiRegexEngineFactory(hscache)
	rsf := secrule.NewReqScannerFactory(mref)
	re := secrule.NewRuleEvaluator()
	reslog := logging.NewZerologResultsLogger(logger)
	sref := secrule.NewEngineFactory(logger, rl, rsf, re, reslog)

	// TODO Implement config manager config restore and pass restored config to NewServer. Also pass the config mgr to the grpc NewServer
	cm, c, err := waf.NewConfigMgr(&waf.ConfigFileSystemImpl{}, &grpc.ConfigConverterImpl{})
	if err != nil {
		logger.Fatal().Err(err).Msg("Error while creating config manager")
	}

	// TODO consider if this should be removed once config management is fully functional e2e
	if *usedefaultwafconfig {
		c = make(map[int]waf.Config)
		c[0] = &mockConfig{}
	}

	w, err := waf.NewServer(logger, c, sref)
	if err != nil {
		logger.Fatal().Err(err).Msg("Error while creating service manager")
	}

	s := grpc.NewServer(w, cm)

	logger.Info().Msg("Starting WAF server")
	if err := s.Serve(); err != nil {
		logger.Fatal().Err(err).Msg("Error while running WAF server")
	}
}
