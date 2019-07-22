package integrationtesting

import (
	"azwaf/hyperscan"
	"azwaf/secrule"
	"azwaf/testutils"
	"github.com/rs/zerolog"
	"testing"
)

func TestSecRuleEngineEvalRequestCrs30(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	origLogLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	defer zerolog.SetGlobalLevel(origLogLevel)
	p := secrule.NewRuleParser()
	rl := secrule.NewCrsRuleLoader(p)
	hsfs := hyperscan.NewCacheFileSystem()
	hscache := hyperscan.NewDbCache(hsfs)
	mref := hyperscan.NewMultiRegexEngineFactory(hscache)
	rsf := secrule.NewReqScannerFactory(mref)
	re := secrule.NewRuleEvaluator()
	reslog := &mockResultsLogger{}
	ef := secrule.NewEngineFactory(logger, rl, rsf, re, reslog)
	e, err := ef.NewEngine(&mockSecRuleConfig{})
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	req := &mockWafHTTPRequest{uri: "http://localhost:8080/", method: "GET"}

	// Act
	r := e.EvalRequest(logger, req)

	// Assert
	if !r {
		t.Fatalf("EvalRequest did not return true")
	}
}