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
	mref := hyperscan.NewMultiRegexEngineFactory()
	rsf := secrule.NewReqScannerFactory(mref)
	ref := secrule.NewRuleEvaluatorFactory()
	ef := secrule.NewEngineFactory(rl, rsf, ref)
	e, err := ef.NewEngine("OWASP CRS 3.0")
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
func (r *mockWafHTTPRequest) BodyReader() io.Reader     { return &bytes.Buffer{} }
