package integrationtesting

import (
	"azwaf/bodyparsing"
	"azwaf/hyperscan"
	"azwaf/secrule"
	"azwaf/testutils"
	"testing"
	"azwaf/waf"

	"github.com/rs/zerolog"
)

func TestNewStandaloneSecruleServerEvalRequestCrs30(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	origLogLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	defer zerolog.SetGlobalLevel(origLogLevel)
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
	var lengthLimits = waf.LengthLimits{
		MaxLengthField:    1024 * 20,         // 20 KiB
		MaxLengthPausable: 1024 * 128,        // 128 KiB
		MaxLengthTotal:    1024 * 1024 * 700, // 700 MiB
	}
	rbp := bodyparsing.NewRequestBodyParser(lengthLimits)
	wafServer, err := waf.NewStandaloneSecruleServer(logger, e, rbp, reslog)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	req := &mockWafHTTPRequest{uri: "http://localhost:8080/", method: "GET"}

	// Act
	decision, err := wafServer.EvalRequest(req)

	// Assert
	if decision != waf.Pass {
		t.Fatalf("EvalRequest did not return pass")
	}
}
