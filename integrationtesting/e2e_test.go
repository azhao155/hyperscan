package integrationtesting

import (
	"azwaf/hyperscan"
	"azwaf/secrule"
	"azwaf/testutils"
	"testing"
	"azwaf/waf"

	"github.com/rs/zerolog"
)

func TestSecRuleEngineEvalRequestCrs30(t *testing.T) {
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
	req := &mockWafHTTPRequest{uri: "http://localhost:8080/", method: "GET"}

	// Act
	ev := e.NewEvaluation(logger, req)
	err = ev.ScanHeaders()
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	r := ev.EvalRules()

	// Assert
	if r != waf.Pass {
		t.Fatalf("EvalRequest did not return pass")
	}
}
