package main

import (
	"azwaf/hyperscan"
	"azwaf/secrule"
	"azwaf/waf"
	"bytes"
	"io"
	"testing"
)

func TestSecRuleEngineEvalRequestCrs30(t *testing.T) {
	// Arrange
	p := secrule.NewRuleParser()
	rl := secrule.NewCrsRuleLoader(p)
	hsfs := hyperscan.NewCacheFileSystem()
	hscache := hyperscan.NewDbCache(hsfs)
	mref := hyperscan.NewMultiRegexEngineFactory(hscache)
	rsf := secrule.NewReqScannerFactory(mref)
	ref := secrule.NewRuleEvaluatorFactory()
	ef := secrule.NewEngineFactory(rl, rsf, ref)
	e, err := ef.NewEngine(&mockSecRuleConfig{})
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	req := &mockWafHTTPRequest{uri: "http://localhost:8080/?1=1"}

	// Act
	r := e.EvalRequest(req)

	// Assert
	if !r {
		t.Fatalf("EvalRequest did not return true")
	}
}

type mockWafHTTPRequest struct {
	uri string
}

func (r *mockWafHTTPRequest) Method() string            { return "GET" }
func (r *mockWafHTTPRequest) URI() string               { return r.uri }
func (r *mockWafHTTPRequest) Headers() []waf.HeaderPair { return nil }
func (r *mockWafHTTPRequest) SecRuleID() string         { return "SecRuleConfig1" }
func (r *mockWafHTTPRequest) Version() int64            { return 0 }
func (r *mockWafHTTPRequest) BodyReader() io.Reader     { return &bytes.Buffer{} }
