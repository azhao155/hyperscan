package main

import (
	"azwaf/grpc"
	"azwaf/hyperscan"
	"azwaf/logging"
	"azwaf/secrule"
	"azwaf/waf"
	"flag"
	"net/http"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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
	flag.Parse()

	if *profiling {
		go func() {
			http.ListenAndServe(":6060", nil)
		}()
	}

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	l, _ := zerolog.ParseLevel(*logLevel)
	zerolog.SetGlobalLevel(l)

	// Depedency injection composition root
	p := secrule.NewRuleParser()
	rl := secrule.NewCrsRuleLoader(p)
	hsfs := hyperscan.NewCacheFileSystem()
	hscache := hyperscan.NewDbCache(hsfs)
	mref := hyperscan.NewMultiRegexEngineFactory(hscache)
	rsf := secrule.NewReqScannerFactory(mref)
	re := secrule.NewRuleEvaluator()
	reslog := logging.NewZerologResultsLogger()
	sref := secrule.NewEngineFactory(rl, rsf, re, reslog)

	// TODO Implement config manager config restore and pass restored config to NewServer. Also pass the config mgr to the grpc NewServer
	cm, c, err := waf.NewConfigMgr(&waf.ConfigFileSystemImpl{}, &grpc.ConfigConverterImpl{})
	if err != nil {
		log.Fatal().Err(err).Msg("Error while creating config manager")
	}

	w, err := waf.NewServer(c, sref)
	if err != nil {
		log.Fatal().Err(err).Msg("Error while creating service manager")
	}

	s := grpc.NewServer(w, cm)

	log.Print("Starting WAF server")
	if err := s.Serve(); err != nil {
		log.Fatal().Err(err).Msg("Error while running WAF server")
	}
}
