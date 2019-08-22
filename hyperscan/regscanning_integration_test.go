package hyperscan

import (
	"azwaf/secrule"
	"azwaf/waf"
	"bytes"
	"io"
	"testing"
)

func TestReqScannerSimpleRules(t *testing.T) {
	// Arrange
	mf := NewMultiRegexEngineFactory(nil)
	rf := secrule.NewReqScannerFactory(mf)
	rules, _ := secrule.NewRuleParser().Parse(`
		SecRule ARGS "ab+c" "id:100"
		SecRule ARGS "abc+" "id:200,chain"
			SecRule ARGS "xyz" "t:lowercase"
		SecRule REQUEST_URI_RAW "a+bc" "id:300,t:lowercase,t:removewhitespace,x"
	`, nil, nil)

	req := &mockWafHTTPRequest{uri: "/hello.php?arg1=ccaaaaaaabccc&arg2=helloworld"}

	// Act
	rs, err1 := rf.NewReqScanner(rules)
	s, err2 := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err3 := rse.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}
	if err3 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	m, ok := sr.GetRxResultsFor(300, 0, "REQUEST_URI_RAW")
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "aaaaaaabc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
	if m.StartPos != 18 {
		t.Fatalf("Unexpected match pos: %d", m.StartPos)
	}
	if m.EndPos != 27 {
		t.Fatalf("Unexpected match pos: %d", m.EndPos)
	}

	m, ok = sr.GetRxResultsFor(200, 0, "ARGS")
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "abccc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
	if m.StartPos != 8 {
		t.Fatalf("Unexpected match StartPos: %d", m.StartPos)
	}
	if m.EndPos != 13 {
		t.Fatalf("Unexpected match EndPos: %d", m.EndPos)
	}

	m, ok = sr.GetRxResultsFor(200, 1, "ARGS")
	if ok {
		t.Fatalf("Unexpected match found")
	}
}

func TestReqScannerPmfRule(t *testing.T) {
	// Arrange
	mf := NewMultiRegexEngineFactory(nil)
	rf := secrule.NewReqScannerFactory(mf)
	rules, _ := secrule.NewRuleParser().Parse(`
		SecRule REQUEST_URI_RAW "@pmf test.data" "id:100"
		`,
		func(fileName string) (phrases []string, err error) {
			return []string{"abc", "def"}, nil
		},
		nil,
	)
	req := &mockWafHTTPRequest{uri: "/hello.php?arg1=ccaaaaaaabccc&arg2=helloworld"}

	// Act
	rs, err1 := rf.NewReqScanner(rules)
	s, err2 := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err3 := rse.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}
	if err3 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	m, ok := sr.GetRxResultsFor(100, 0, "REQUEST_URI_RAW")
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "abc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
}

func TestReqScannerPmfRuleNotCaseSensitive(t *testing.T) {
	// Arrange
	mf := NewMultiRegexEngineFactory(nil)
	rf := secrule.NewReqScannerFactory(mf)
	rules, _ := secrule.NewRuleParser().Parse(`
		SecRule REQUEST_URI_RAW "@pmf test.data" "id:100"
		`,
		func(fileName string) (phrases []string, err error) {
			return []string{"abC", "def"}, nil
		},
		nil,
	)
	req := &mockWafHTTPRequest{uri: "/hello.php?arg1=ccaaaaaaaBccc&arg2=helloworld"}

	// Act
	rs, err1 := rf.NewReqScanner(rules)
	s, err2 := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err3 := rse.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}
	if err3 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	m, ok := sr.GetRxResultsFor(100, 0, "REQUEST_URI_RAW")
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "aBc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
}

type mockWafHTTPRequest struct {
	uri string
}

func (r *mockWafHTTPRequest) Method() string            { return "GET" }
func (r *mockWafHTTPRequest) URI() string               { return r.uri }
func (r *mockWafHTTPRequest) Headers() []waf.HeaderPair { return nil }
func (r *mockWafHTTPRequest) ConfigID() string          { return "SecRuleConfig1" }
func (r *mockWafHTTPRequest) BodyReader() io.Reader     { return &bytes.Buffer{} }
