package hyperscan

import (
	ast "azwaf/secrule/ast"
	srrs "azwaf/secrule/reqscanning"
	srrp "azwaf/secrule/ruleparsing"

	"azwaf/waf"
	"bytes"
	"io"
	"testing"
)

func TestReqScannerSimpleRules(t *testing.T) {
	// Arrange
	mf := NewMultiRegexEngineFactory(nil)
	rf := srrs.NewReqScannerFactory(mf)
	rules, _ := srrp.NewRuleParser().Parse(`
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
	sr := srrs.NewScanResults()
	err3 := rse.ScanHeaders(req, sr)

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

	m, ok := sr.GetResultsFor(300, 0, ast.Target{Name: ast.TargetRequestURIRaw})
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m[0].Data) != "aaaaaaabc" {
		t.Fatalf("Unexpected match data: %s", string(m[0].Data))
	}

	m, ok = sr.GetResultsFor(200, 0, ast.Target{Name: ast.TargetArgs})
	if !ok {
		t.Fatalf("Match not found")
	}
	if len(m) != 1 {
		t.Fatalf("Unexpected number of matches: %v", len(m))
	}
	if string(m[0].Data) != "abccc" {
		t.Fatalf("Unexpected match data: %s", string(m[0].Data))
	}

	m, ok = sr.GetResultsFor(200, 1, ast.Target{Name: ast.TargetArgs})
	if ok {
		t.Fatalf("Unexpected match found")
	}
}

func TestReqScannerPmfRule(t *testing.T) {
	// Arrange
	mf := NewMultiRegexEngineFactory(nil)
	rf := srrs.NewReqScannerFactory(mf)
	rules, _ := srrp.NewRuleParser().Parse(`
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
	sr := srrs.NewScanResults()
	err3 := rse.ScanHeaders(req, sr)

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

	m, ok := sr.GetResultsFor(100, 0, ast.Target{Name: ast.TargetRequestURIRaw})
	if !ok {
		t.Fatalf("Match not found")
	}
	if len(m) != 1 {
		t.Fatalf("Unexpected number of matches: %v", len(m))
	}
	if string(m[0].Data) != "abc" {
		t.Fatalf("Unexpected match data: %s", string(m[0].Data))
	}
}

func TestReqScannerPmfRuleNotCaseSensitive(t *testing.T) {
	// Arrange
	mf := NewMultiRegexEngineFactory(nil)
	rf := srrs.NewReqScannerFactory(mf)
	rules, _ := srrp.NewRuleParser().Parse(`
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
	sr := srrs.NewScanResults()
	err3 := rse.ScanHeaders(req, sr)

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

	m, ok := sr.GetResultsFor(100, 0, ast.Target{Name: ast.TargetRequestURIRaw})
	if !ok {
		t.Fatalf("Match not found")
	}
	if len(m) != 1 {
		t.Fatalf("Unexpected number of matches: %v", len(m))
	}
	if string(m[0].Data) != "aBc" {
		t.Fatalf("Unexpected match data: %s", string(m[0].Data))
	}
}

type mockWafHTTPRequest struct {
	uri string
}

func (r *mockWafHTTPRequest) Method() string                      { return "GET" }
func (r *mockWafHTTPRequest) URI() string                         { return r.uri }
func (r *mockWafHTTPRequest) Protocol() string                    { return "HTTP/1.1" }
func (r *mockWafHTTPRequest) RemoteAddr() string                  { return "0.0.0.0" }
func (r *mockWafHTTPRequest) Headers() []waf.HeaderPair           { return nil }
func (r *mockWafHTTPRequest) ConfigID() string                    { return "SecRuleConfig1" }
func (r *mockWafHTTPRequest) BodyReader() io.Reader               { return &bytes.Buffer{} }
func (r *mockWafHTTPRequest) LogMetaData() waf.RequestLogMetaData { return &mockLogMetaData{} }
func (r *mockWafHTTPRequest) TransactionID() string               { return "abc" }

type mockLogMetaData struct {
}

func (h *mockLogMetaData) Scope() string     { return "Global" }
func (h *mockLogMetaData) ScopeName() string { return "Default Policy" }
