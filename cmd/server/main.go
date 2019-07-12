package main

import (
	"azwaf/grpc"
	"azwaf/hyperscan"
	"azwaf/logging"
	"azwaf/secrule"
	"azwaf/waf"

	log "github.com/sirupsen/logrus"
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
	//log.SetLevel(log.TraceLevel)
	log.SetLevel(log.InfoLevel)

	// Depedency injection composition root
	p := secrule.NewRuleParser()
	rl := secrule.NewCrsRuleLoader(p)
	hsfs := hyperscan.NewCacheFileSystem()
	hscache := hyperscan.NewDbCache(hsfs)
	mref := hyperscan.NewMultiRegexEngineFactory(hscache)
	rsf := secrule.NewReqScannerFactory(mref)
	ref := secrule.NewRuleEvaluatorFactory()
	reslog := logging.NewLogrusResultsLogger()
	sref := secrule.NewEngineFactory(rl, rsf, ref, reslog)

	// TODO Implement config manager config restore and pass restored config to NewServer. Also pass the config mgr to the grpc NewServer
	cm, _, err := waf.NewConfigMgr(&waf.ConfigFileSystemImpl{}, &grpc.ConfigConverterImpl{})
	if err != nil {
		log.Fatalf("error while creating config manager: %v", err)
	}

	// TODO Implement real config loading.
	c := make(map[int64]waf.Config)
	c[0] = &mockConfig{}

	w, err := waf.NewServer(c, sref)
	if err != nil {
		log.Fatalf("error while creating service manager: %v", err)
	}

	s := grpc.NewServer(w, cm)

	log.Print("Starting WAF server")
	if err := s.Serve(); err != nil {
		log.Fatalf("%v", err)
	}
}
