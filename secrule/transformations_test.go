package secrule

import (
	"fmt"
	"strings"
	"testing"
)

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
		rules := []Statement{&Rule{ID: 100, Items: []RuleItem{{Predicate: RulePredicate{Targets: []string{test.target}, Op: Rx, Val: "abc"}, Transformations: test.inputTransformations}}}}
		req := &mockWafHTTPRequest{uri: test.inputURI}
		rs, err1 := rsf.NewReqScanner(rules)

		// Act
		_, err2 := rs.ScanHeaders(req)

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
