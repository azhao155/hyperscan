package secrule

import (
	"azwaf/waf"
	"bytes"
	"fmt"
	"io"
	"strings"
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

func TestTransformations(t *testing.T) {
	// Arrange
	type testcase struct {
		inputVal             string
		inputTransformations []Transformation
		expected             string
	}
	tests := []testcase{
		{`hello%20world`, []Transformation{}, `hello%20world`},
		{`AAAAAAABCCC`, []Transformation{Lowercase}, `aaaaaaabccc`},
		{`hello%20world`, []Transformation{URLDecodeUni}, `hello world`},
		{`hello world`, []Transformation{RemoveWhitespace}, `helloworld`},
		{` hello world `, []Transformation{RemoveWhitespace}, `helloworld`},
		{"hello\tworld", []Transformation{RemoveWhitespace}, `helloworld`},
		{"hello\nworld", []Transformation{RemoveWhitespace}, `helloworld`},
		{"hello\rworld", []Transformation{RemoveWhitespace}, `helloworld`},
		{"hello \t\n\r world", []Transformation{RemoveWhitespace}, `helloworld`},
		{`hello &lt;i&gt;world&lt;/i&gt;`, []Transformation{HTMLEntityDecode}, `hello <i>world</i>`},

		// Combinations
		{`AAAAAAA%20BCCC`, []Transformation{Lowercase, URLDecodeUni}, `aaaaaaa bccc`},
		{`AAAAAAA%20BCCC`, []Transformation{Lowercase, RemoveWhitespace, URLDecodeUni}, `aaaaaaa bccc`}, // Not removing space because URLDecodeUni hasn't yet turned %20 into space
		{`AAAAAAA%20BCCC`, []Transformation{Lowercase, URLDecodeUni, RemoveWhitespace}, `aaaaaaabccc`},
	}

	// Act and assert
	var b strings.Builder
	for i, test := range tests {
		// Act
		s := applyTransformations(test.inputVal, test.inputTransformations)

		// Assert
		if s != test.expected {
			fmt.Fprintf(&b, "Test %v, input %v. Bad transformation. Expected: %v. Actual: %v\n", i+1, test.inputVal, test.expected, s)
			continue
		}
	}

	if b.Len() > 0 {
		t.Fatalf("\n%s", b.String())
	}
}

func TestTransformationsViaReqScanner(t *testing.T) {
	// Arrange

	// A multi-regex engine mock that just keeps track of what we asked it to scan for.
	var scannedFor []string
	mf := &mockMultiRegexEngineFactory{
		newMultiRegexEngineMockFunc: func(mm []MultiRegexEnginePattern) MultiRegexEngine {
			return &mockMultiRegexEngine{
				scanMockFunc: func(input []byte) []MultiRegexEngineMatch {
					scannedFor = append(scannedFor, string(input))
					return nil
				},
			}
		},
	}

	rsf := NewReqScannerFactory(mf)

	type testcase struct {
		inputURI             string
		inputTransformations []Transformation
		target               string
		expected             string
	}
	tests := []testcase{
		{`/a.php?arg1=AAAAAAABCCC`, []Transformation{Lowercase}, "ARGS", `aaaaaaabccc`},
		{`/a.php?arg1=hello%20world`, []Transformation{}, "ARGS", `hello world`}, // ARGS is always already URL-decoded during ARGS parsing.
		{`/a.php?arg1=hello%20world`, []Transformation{}, "REQUEST_URI_RAW", `/a.php?arg1=hello%20world`},
		{`/a.php?arg1=hello%20world`, []Transformation{URLDecodeUni}, "REQUEST_URI_RAW", `/a.php?arg1=hello world`},
		{`/a.php?arg1=AAAAAAA%20BCCC`, []Transformation{Lowercase, URLDecodeUni}, "REQUEST_URI_RAW", `/a.php?arg1=aaaaaaa bccc`},
	}

	var b strings.Builder
	for i, test := range tests {
		scannedFor = []string{}
		rules := []Rule{{ID: 100, Items: []RuleItem{{Predicate: RulePredicate{Targets: []string{test.target}, Op: Rx, Val: "abc"}, Transformations: test.inputTransformations}}}}
		req := &mockWafHTTPRequest{uri: test.inputURI}
		rs, err1 := rsf.NewReqScanner(rules)

		// Act
		_, err2 := rs.Scan(req)

		// Assert
		if err1 != nil {
			fmt.Fprintf(&b, "Test %v. Got unexpected error: %v\n", i+1, err1)
			continue
		}

		if err2 != nil {
			fmt.Fprintf(&b, "Test %v. Got unexpected error: %v\n", i+1, err2)
			continue
		}

		n := len(scannedFor)
		if n != 1 {
			fmt.Fprintf(&b, "Test %v. Only expected 1 scan to happen. Unexpected number of scans happened: %v\n", i+1, n)
			continue
		}

		if scannedFor[0] != test.expected {
			fmt.Fprintf(&b, "Test %v. A scan for an unexpected string happened. Expected: %v. Actual: %v\n", i+1, test.expected, scannedFor[0])
			continue
		}
	}

	if b.Len() > 0 {
		t.Fatalf("\n%s", b.String())
	}
}

type mockWafHTTPRequest struct {
	uri string
}

func (r *mockWafHTTPRequest) Method() string            { return "GET" }
func (r *mockWafHTTPRequest) URI() string               { return r.uri }
func (r *mockWafHTTPRequest) Headers() []waf.HeaderPair { return nil }
func (r *mockWafHTTPRequest) BodyReader() io.Reader     { return &bytes.Buffer{} }
