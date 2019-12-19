package integrationtesting

import (
	sreng "azwaf/secrule/engine"
	srrs "azwaf/secrule/reqscanning"
	srre "azwaf/secrule/ruleevaluation"
	srrp "azwaf/secrule/ruleparsing"

	"azwaf/bodyparsing"
	"azwaf/customrule"
	"azwaf/geodb"
	"azwaf/hyperscan"
	"azwaf/ipreputation"
	"azwaf/logging"
	"azwaf/testutils"
	"azwaf/waf"
	"testing"
)

func newTestStandaloneSecruleServer(t *testing.T) waf.Server {
	logger := testutils.NewTestLogger(t)
	p := srrp.NewRuleParser()
	rlfs := srrp.NewRuleLoaderFileSystem()
	rl := srrp.NewCrsRuleLoader(p, rlfs)
	hsfs := hyperscan.NewCacheFileSystem()
	hscache := hyperscan.NewDbCache(hsfs)
	mref := hyperscan.NewMultiRegexEngineFactory(hscache)
	rsf := srrs.NewReqScannerFactory(mref)
	ref := srre.NewRuleEvaluatorFactory()
	reslog := newMockResultsLogger()
	rlf := &mockResultsLoggerFactory{mockResultsLogger: reslog}
	ef := sreng.NewEngineFactory(logger, rl, rsf, ref)
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
	p := srrp.NewRuleParser()
	rlfs := &mockRuleLoaderFileSystem{}
	rl := srrp.NewCrsRuleLoader(p, rlfs)
	hsfs := hyperscan.NewCacheFileSystem()
	hscache := hyperscan.NewDbCache(hsfs)
	mref := hyperscan.NewMultiRegexEngineFactory(hscache)
	rsf := srrs.NewReqScannerFactory(mref)
	ref := srre.NewRuleEvaluatorFactory()
	sref := sreng.NewEngineFactory(logger, rl, rsf, ref)

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
