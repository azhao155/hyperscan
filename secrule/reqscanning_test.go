package secrule

import (
	"azwaf/waf"
	"bytes"
	"io"
	"testing"
)

func TestReqScanner1(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules, _ := newMockRuleLoader().Rules("some ruleset")
	req := &mockWafHTTPRequest{uri: "/hello.php?arg1=aaaaaaabccc"}

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	sr, err2 := rs.Scan(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	m, ok := sr.GetRxResultsFor(300, 0, "REQUEST_URI_RAW")
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "aaaaaaabc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
	if m.StartPos != 16 {
		t.Fatalf("Unexpected match pos: %d", m.StartPos)
	}
	if m.EndPos != 25 {
		t.Fatalf("Unexpected match pos: %d", m.EndPos)
	}

	m, ok = sr.GetRxResultsFor(200, 0, "ARGS")
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "abccc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
	if m.StartPos != 6 {
		t.Fatalf("Unexpected match pos: %d", m.StartPos)
	}
	if m.EndPos != 11 {
		t.Fatalf("Unexpected match pos: %d", m.EndPos)
	}

	m, ok = sr.GetRxResultsFor(200, 1, "ARGS")
	if ok {
		t.Fatalf("Unexpected match found")
	}
}

func TestGetExprsRx(t *testing.T) {
	r1 := &RuleItem{Predicate: RulePredicate{Op: Rx, Val: "abc+"}}
	ee := getRxExprs(r1)
	if ee == nil {
		t.Fatalf("Expressions should not be nil")
	}

	if len(ee) != 1 {
		t.Fatalf("Unexpected expression count %d", len(ee))
	}

	if ee[0] != "abc+" {
		t.Fatalf("Invalid expression %s", ee[0])
	}
}

func TestGetExprsPmf(t *testing.T) {
	r1 := &RuleItem{Predicate: RulePredicate{Op: Pmf}, PmPhrases: []string{"abc", "def"}}
	ee := getRxExprs(r1)
	if ee == nil {
		t.Fatalf("Expressions should not be nil")
	}

	if len(ee) != 2 {
		t.Fatalf("Unexpected expression count %d", len(ee))
	}

	if ee[0] != "abc" {
		t.Fatalf("Invalid expression %s", ee[0])
	}

	if ee[1] != "def" {
		t.Fatalf("Invalid expression %s", ee[1])
	}
}

func TestReqScannerBodyMultipart1(t *testing.T) {
	// Arrange
	body := `--------------------------1aa6ce6559102
content-disposition: form-data; name="a"

hello world 1
--------------------------1aa6ce6559102
content-disposition: form-data; name="b"

aaaaaaabccc
--------------------------1aa6ce6559102--
`
	rs, req := arrangeReqScannerForBodyParsing(t, "ARGS", "multipart/form-data; boundary=------------------------1aa6ce6559102", body)

	// Act
	sr, err := rs.Scan(req)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	m, ok := sr.GetRxResultsFor(200, 0, "ARGS")
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "abccc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
	if m.StartPos != 6 {
		t.Fatalf("Unexpected match pos: %d", m.StartPos)
	}
	if m.EndPos != 11 {
		t.Fatalf("Unexpected match pos: %d", m.EndPos)
	}
}

func TestReqScannerBodyMultipart1Negative(t *testing.T) {
	// Arrange
	body := `--------------------------1aa6ce6559102
content-disposition: form-data; name="a"

hello world 1
--------------------------1aa6ce6559102
content-disposition: form-data; name="b"

hello world 2
--------------------------1aa6ce6559102--
`
	rs, req := arrangeReqScannerForBodyParsing(t, "ARGS", "multipart/form-data; boundary=------------------------1aa6ce6559102", body)

	// Act
	sr, err := rs.Scan(req)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	_, ok := sr.GetRxResultsFor(200, 0, "ARGS")
	if ok {
		t.Fatalf("Unexpected match found")
	}
}

func TestReqScannerBodyMultipartSkipFile(t *testing.T) {
	// Arrange
	body := `--------------------------1aa6ce6559102
content-disposition: form-data; name="a"

hello world 1
--------------------------1aa6ce6559102
content-disposition: form-data; name="b"; filename="vcredist_x64.exe"

aaaaaaabccc
--------------------------1aa6ce6559102--
`
	rs, req := arrangeReqScannerForBodyParsing(t, "ARGS", "multipart/form-data; boundary=------------------------1aa6ce6559102", body)

	// Act
	sr, err := rs.Scan(req)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	_, ok := sr.GetRxResultsFor(200, 0, "ARGS")
	if ok {
		t.Fatalf("Unexpected match found")
	}
}

func TestReqScannerBodyJSON1(t *testing.T) {
	// Arrange
	body := `
		{
			"a": [1,2,3],
			"b": "aaaaaaabccc"
		}
	`
	rs, req := arrangeReqScannerForBodyParsing(t, "XML:/*", "application/json", body)

	// Act
	sr, err := rs.Scan(req)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	m, ok := sr.GetRxResultsFor(200, 0, "XML:/*")
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "abccc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
	if m.StartPos != 6 {
		t.Fatalf("Unexpected match pos: %d", m.StartPos)
	}
	if m.EndPos != 11 {
		t.Fatalf("Unexpected match pos: %d", m.EndPos)
	}
}

func TestReqScannerBodyJSON1Negative(t *testing.T) {
	// Arrange
	body := `
		{
			"a": [1,2,3],
			"b": "hello world"
		}
	`
	rs, req := arrangeReqScannerForBodyParsing(t, "XML:/*", "application/json", body)

	// Act
	sr, err := rs.Scan(req)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	_, ok := sr.GetRxResultsFor(200, 0, "XML:/*")
	if ok {
		t.Fatalf("Unexpected match found")
	}
}

func TestReqScannerBodyJSONParseErr(t *testing.T) {
	// Arrange
	body := `
		{
			"a": [1,2,3],
			"b": "hello world",
			nonsense
		}
	`
	rs, req := arrangeReqScannerForBodyParsing(t, "XML:/*", "application/json", body)

	// Act
	_, err := rs.Scan(req)

	// Assert
	if err == nil {
		t.Fatalf("Expected error, but got nil")
	}
}

func TestReqScannerBodyXML1(t *testing.T) {
	// Arrange
	body := `
		<hello>
			<world>aaaaaaabccc</world>
		</hello>
	`
	rs, req := arrangeReqScannerForBodyParsing(t, "XML:/*", "text/xml", body)

	// Act
	sr, err := rs.Scan(req)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	m, ok := sr.GetRxResultsFor(200, 0, "XML:/*")
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "abccc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
	if m.StartPos != 6 {
		t.Fatalf("Unexpected match pos: %d", m.StartPos)
	}
	if m.EndPos != 11 {
		t.Fatalf("Unexpected match pos: %d", m.EndPos)
	}
}

func TestReqScannerBodyXML1Negative(t *testing.T) {
	// Arrange
	body := `
		<hello>
			<world>hello world</world>
		</hello>
	`
	rs, req := arrangeReqScannerForBodyParsing(t, "XML:/*", "text/xml", body)

	// Act
	sr, err := rs.Scan(req)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	_, ok := sr.GetRxResultsFor(200, 0, "XML:/*")
	if ok {
		t.Fatalf("Unexpected match found")
	}
}

func TestReqScannerBodyXMLParseError(t *testing.T) {
	// Arrange
	body := `
		<hello>
			<world>hello world</nonsense>
		</hello>
	`
	rs, req := arrangeReqScannerForBodyParsing(t, "XML:/*", "text/xml", body)

	// Act
	_, err := rs.Scan(req)

	// Assert
	if err == nil {
		t.Fatalf("Expected error, but got nil")
	}
}

func arrangeReqScannerForBodyParsing(t *testing.T, target string, contentType string, body string) (rs ReqScanner, req waf.HTTPRequest) {
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Rule{
		{
			ID: 200,
			Items: []RuleItem{
				{Predicate: RulePredicate{Targets: []string{target}, Op: Rx, Val: "abc+"}},
			},
		},
	}
	uri := "/"
	headers := []waf.HeaderPair{
		&mockHeaderPair{k: "Content-Type", v: contentType},
	}
	req = &mockWafHTTPRequest{uri: uri, headers: headers, bodyReader: bytes.NewBufferString(body)}
	rs, err := rsf.NewReqScanner(rules)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	return
}

func TestReqScannerBodyUrlencode1(t *testing.T) {
	// Arrange
	body := `a=helloworld1&b=aaaaaaabccc`
	rs, req := arrangeReqScannerForBodyParsing(t, "ARGS", "application/x-www-form-urlencoded", body)

	// Act
	sr, err := rs.Scan(req)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	m, ok := sr.GetRxResultsFor(200, 0, "ARGS")
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "abccc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
	if m.StartPos != 6 {
		t.Fatalf("Unexpected match pos: %d", m.StartPos)
	}
	if m.EndPos != 11 {
		t.Fatalf("Unexpected match pos: %d", m.EndPos)
	}
}

func TestReqScannerBodyUrlencode1Negative(t *testing.T) {
	// Arrange
	body := `a=helloworld1&b=helloworld2`
	rs, req := arrangeReqScannerForBodyParsing(t, "ARGS", "application/x-www-form-urlencoded", body)

	// Act
	sr, err := rs.Scan(req)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	_, ok := sr.GetRxResultsFor(200, 0, "ARGS")
	if ok {
		t.Fatalf("Unexpected match found")
	}
}

type mockWafHTTPRequest struct {
	uri        string
	bodyReader io.Reader
	headers    []waf.HeaderPair
}

func (r *mockWafHTTPRequest) Method() string            { return "GET" }
func (r *mockWafHTTPRequest) URI() string               { return r.uri }
func (r *mockWafHTTPRequest) Headers() []waf.HeaderPair { return r.headers }
func (r *mockWafHTTPRequest) BodyReader() io.Reader     { return r.bodyReader }

type mockHeaderPair struct {
	k string
	v string
}

func (h *mockHeaderPair) Key() string   { return h.k }
func (h *mockHeaderPair) Value() string { return h.v }
