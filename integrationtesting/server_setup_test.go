package integrationtesting

import (
	"azwaf/bodyparsing"
	"azwaf/customrule"
	"azwaf/geodb"
	"azwaf/hyperscan"
	"azwaf/ipreputation"
	"azwaf/logging"
	"azwaf/secrule"
	"azwaf/testutils"
	"azwaf/waf"
	"testing"
)

var defaultLengthLimits = waf.LengthLimits{
	MaxLengthField:    1024 * 20,         // 20 KiB
	MaxLengthPausable: 1024 * 128,        // 128 KiB
	MaxLengthTotal:    1024 * 1024 * 700, // 700 MiB
}

func newTestStandaloneSecruleServer(t *testing.T) waf.Server {
	logger := testutils.NewTestLogger(t)
	p := secrule.NewRuleParser()
	rlfs := secrule.NewRuleLoaderFileSystem()
	rl := secrule.NewCrsRuleLoader(p, rlfs)
	hsfs := hyperscan.NewCacheFileSystem()
	hscache := hyperscan.NewDbCache(hsfs)
	mref := hyperscan.NewMultiRegexEngineFactory(hscache)
	rsf := secrule.NewReqScannerFactory(mref)
	re := secrule.NewRuleEvaluator()
	reslog := &mockResultsLogger{}
	ef := secrule.NewEngineFactory(logger, rl, rsf, re, reslog)
	e, err := ef.NewEngine(&mockSecRuleConfig{ruleSetID: "OWASP CRS 3.0"})
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	rbp := bodyparsing.NewRequestBodyParser(defaultLengthLimits)
	wafServer, err := waf.NewStandaloneSecruleServer(logger, e, rbp, reslog)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	return wafServer
}

func newTestAzwafServer(t *testing.T) waf.Server {
	// Setup logger.
	logger := testutils.NewTestLogger(t)
	log, err := logging.NewFileResultsLogger(&logging.LogFileSystemImpl{}, logger)

	// Setup config manager
	cm, c, err := waf.NewConfigMgr(&mockFileSystem{}, &mockConfigConverter{})
	if err != nil {
		logger.Fatal().Err(err).Msg("Error while creating config manager")
	}

	// Setup secrule engine
	p := secrule.NewRuleParser()
	rlfs := &mockRuleLoaderFileSystem{}
	rl := secrule.NewCrsRuleLoader(p, rlfs)
	hsfs := hyperscan.NewCacheFileSystem()
	hscache := hyperscan.NewDbCache(hsfs)
	mref := hyperscan.NewMultiRegexEngineFactory(hscache)
	rsf := secrule.NewReqScannerFactory(mref)
	re := secrule.NewRuleEvaluator()
	sref := secrule.NewEngineFactory(logger, rl, rsf, re, log)

	rbp := bodyparsing.NewRequestBodyParser(defaultLengthLimits)

	// Setup customrule engine
	gfs := geodb.NewGeoIPFileSystem(logger)
	geoDB := geodb.NewGeoDB(logger, gfs)
	crl := customrule.NewCustomRuleLoader(geoDB)
	cref := customrule.NewEngineFactory(logger, crl, rsf, re)
	ire := ipreputation.NewIPReputationEngine(&mockIreFileSystem{})
	wafServer, err := waf.NewServer(logger, cm, c, sref, rbp, log, cref, ire, geoDB)

	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	return wafServer
}
