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
	reslog := newMockResultsLogger()
	rlf := &mockResultsLoggerFactory{mockResultsLogger: reslog}
	ef := secrule.NewEngineFactory(logger, rl, rsf, re)
	e, err := ef.NewEngine(&mockSecRuleConfig{ruleSetID: "OWASP CRS 3.0"})
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	rbp := bodyparsing.NewRequestBodyParser(waf.DefaultLengthLimits)
	wafServer, err := waf.NewStandaloneSecruleServer(logger, rlf, e, rbp)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	return wafServer
}

func newTestAzwafServer(t *testing.T) waf.Server {
	// Setup logger.
	logger := testutils.NewTestLogger(t)
	reopenLogFileChan := make(chan bool)
	rlf, err := logging.NewFileLogResultsLoggerFactory(&logging.LogFileSystemImpl{}, logger, reopenLogFileChan)

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
	sref := secrule.NewEngineFactory(logger, rl, rsf, re)

	rbp := bodyparsing.NewRequestBodyParser(waf.DefaultLengthLimits)

	// Setup customrule engine
	gfs := &mockGeoDBFileSystem{}
	geoDB := geodb.NewGeoDB(logger, gfs)
	cref := customrule.NewEngineFactory(mref, geoDB)
	ire := ipreputation.NewIPReputationEngine(&mockIreFileSystem{})
	wafServer, err := waf.NewServer(logger, cm, c, rlf, sref, rbp, cref, ire, geoDB)

	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	return wafServer
}
