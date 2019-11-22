package secrule

import (
	"azwaf/waf"
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
		{`hello+world`, []Transformation{URLDecodeUni}, `hello world`},
		{`hello%ggworld`, []Transformation{URLDecodeUni}, `hello%ggworld`},
		{`hello%20`, []Transformation{URLDecodeUni}, `hello `},
		{`hello%2`, []Transformation{URLDecodeUni}, `hello%2`},
		{`hello%`, []Transformation{URLDecodeUni}, `hello%`},
		{`%20`, []Transformation{URLDecodeUni}, ` `},
		{`%2`, []Transformation{URLDecodeUni}, `%2`},
		{`%`, []Transformation{URLDecodeUni}, `%`},
		{``, []Transformation{URLDecodeUni}, ``},
		{`%00`, []Transformation{URLDecodeUni}, "\x00"},
		{`x%6ax`, []Transformation{URLDecodeUni}, `xjx`},
		{`x%6Ax`, []Transformation{URLDecodeUni}, `xjx`},

		{`hello world`, []Transformation{RemoveWhitespace}, `helloworld`},
		{` hello world `, []Transformation{RemoveWhitespace}, `helloworld`},
		{"hello\tworld", []Transformation{RemoveWhitespace}, `helloworld`},
		{"hello\nworld", []Transformation{RemoveWhitespace}, `helloworld`},
		{"hello\rworld", []Transformation{RemoveWhitespace}, `helloworld`},
		{"hello \t\n\r world", []Transformation{RemoveWhitespace}, `helloworld`},
		{"hello \xa0 world", []Transformation{RemoveWhitespace}, `helloworld`},

		{`hello &lt;i&gt;world&lt;/i&gt;`, []Transformation{HTMLEntityDecode}, `hello <i>world</i>`},

		{"hello world", []Transformation{Utf8toUnicode}, "hello world"},
		{"hello Ø world", []Transformation{Utf8toUnicode}, "hello %u00d8 world"},
		{"hello 你好 world", []Transformation{Utf8toUnicode}, "hello %u4f60%u597d world"},
		{"hello 你 world", []Transformation{Utf8toUnicode}, "hello %u4f60 world"},
		{"hello \xe4\xbd\xa0 world", []Transformation{Utf8toUnicode}, "hello %u4f60 world"},
		{"hello \xff\xbd\xa0 world", []Transformation{Utf8toUnicode}, "hello \xff\xbd\xa0 world"},                 // Invalid UTF-8 sequences should remain untouched
		{"hello \xe4\xff\xa0 world", []Transformation{Utf8toUnicode}, "hello \xe4\xff\xa0 world"},                 // Invalid UTF-8 sequences should remain untouched
		{"hello \xe4\xbd\xff world", []Transformation{Utf8toUnicode}, "hello \xe4\xbd\xff world"},                 // Invalid UTF-8 sequences should remain untouched
		{"hello \xFF\xFF\xFF\xFF\xFF world", []Transformation{Utf8toUnicode}, "hello \xFF\xFF\xFF\xFF\xFF world"}, // Invalid UTF-8 sequences should remain untouched
		{"hello 你好 \xFF\xFF\xFF\xFF\xFF \xe4\xbd\xa0 world", []Transformation{Utf8toUnicode}, "hello %u4f60%u597d \xFF\xFF\xFF\xFF\xFF %u4f60 world"},

		{`hello \' world`, []Transformation{JsDecode}, `hello ' world`},
		{`hello \" world`, []Transformation{JsDecode}, `hello " world`},
		{`hello \b world`, []Transformation{JsDecode}, "hello \b world"},
		{`hello \f world`, []Transformation{JsDecode}, "hello \f world"},
		{`hello \n world`, []Transformation{JsDecode}, "hello \n world"},
		{`hello \r world`, []Transformation{JsDecode}, "hello \r world"},
		{`hello \t world`, []Transformation{JsDecode}, "hello \t world"},
		{`hello \v world`, []Transformation{JsDecode}, "hello \v world"},
		{`hello \u4f60\u597d world`, []Transformation{JsDecode}, `hello 你好 world`},
		{`hi \uff48\uff45\uff4c\uff4c\uff4f world`, []Transformation{JsDecode}, `hi hello world`}, // Special handling of full-width ｈｅｌｌｏ
		{`hi \u{4f60} world`, []Transformation{JsDecode}, `hi 你 world`},
		{`\u{4f60}`, []Transformation{JsDecode}, `你`},
		{`hello \umf60 world`, []Transformation{JsDecode}, `hello umf60 world`}, // Fallback in case of invalid hex
		{`hello \u4m60 world`, []Transformation{JsDecode}, `hello u4m60 world`}, // Fallback in case of invalid hex
		{`hello \u4fm0 world`, []Transformation{JsDecode}, `hello u4fm0 world`}, // Fallback in case of invalid hex
		{`hello \u4f6m world`, []Transformation{JsDecode}, `hello u4f6m world`}, // Fallback in case of invalid hex
		{`hello \xFF world`, []Transformation{JsDecode}, "hello \xFF world"},
		{`hello \xff world`, []Transformation{JsDecode}, "hello \xFF world"},
		{`hello \x4D world`, []Transformation{JsDecode}, "hello M world"},
		{`hello \x4d world`, []Transformation{JsDecode}, "hello M world"},
		{`hello \x4m world`, []Transformation{JsDecode}, "hello x4m world"},          // Fallback in case of invalid hex
		{`hello \xmm world`, []Transformation{JsDecode}, `hello xmm world`},          // Fallback in case of invalid hex
		{`hello \251 world`, []Transformation{JsDecode}, "hello \xa9 world"},         // Octal notation
		{`hello \1 world`, []Transformation{JsDecode}, "hello \x01 world"},           // Octal notation
		{`hello \1a world`, []Transformation{JsDecode}, "hello \x01a world"},         // Octal notation
		{`hello \01 world`, []Transformation{JsDecode}, "hello \x01 world"},          // Octal notation
		{`hello \01a world`, []Transformation{JsDecode}, "hello \x01a world"},        // Octal notation
		{`hello \001 world`, []Transformation{JsDecode}, "hello \x01 world"},         // Octal notation
		{`hello \001a world`, []Transformation{JsDecode}, "hello \x01a world"},       // Octal notation
		{`hello \1\xff world`, []Transformation{JsDecode}, "hello \x01\xff world"},   // Octal notation followed by another escape
		{`hello \01\xff world`, []Transformation{JsDecode}, "hello \x01\xff world"},  // Octal notation followed by another escape
		{`hello \001\xff world`, []Transformation{JsDecode}, "hello \x01\xff world"}, // Octal notation followed by another escape
		{`hello \1world`, []Transformation{JsDecode}, "hello \x01world"},             // Octal notation
		{`hello \1\tworld`, []Transformation{JsDecode}, "hello \x01\tworld"},         // Octal notation
		{`hello \a world`, []Transformation{JsDecode}, "hello a world"},              // Fallback for invalid escape
		{`hello \u{1F603} world`, []Transformation{JsDecode}, "hello 😃 world"},
		{`hello \u{110000} world`, []Transformation{JsDecode}, "hello u{110000} world"},  // Fallback for code point falling outside the range of unicode
		{`hello \u{10FFFE} world`, []Transformation{JsDecode}, "hello \U0010FFFE world"}, // At the very edge of valid unicode code points
		{`hello \u{10FFFF} world`, []Transformation{JsDecode}, "hello \U0010FFFF world"}, // At the very edge of valid unicode code points
		{`hello \u{00000000000000000000000000000000001F603} world`, []Transformation{JsDecode}, "hello 😃 world"},
		{`hello \u{1F60m} world`, []Transformation{JsDecode}, "hello u{1F60m} world"},
		{`hello \`, []Transformation{JsDecode}, "hello "},                                                    // Incomplete escape at the edge
		{`hello \u1F`, []Transformation{JsDecode}, "hello u1F"},                                              // Incomplete escape at the edge
		{`hello \u{1F`, []Transformation{JsDecode}, "hello u{1F"},                                            // Incomplete escape at the edge
		{`hello \1`, []Transformation{JsDecode}, "hello \x01"},                                               // Octal escape at the edge
		{`hello \01`, []Transformation{JsDecode}, "hello \x01"},                                              // Octal escape at the edge
		{`hello \001`, []Transformation{JsDecode}, "hello \x01"},                                             // Octal escape at the edge
		{"hello \xff\xbd\xa0 world", []Transformation{JsDecode}, "hello \xff\xbd\xa0 world"},                 // JsDecode should not change binary content
		{"hello \xe4\xff\xa0 world", []Transformation{JsDecode}, "hello \xe4\xff\xa0 world"},                 // JsDecode should not change binary content
		{"hello \xe4\xbd\xff world", []Transformation{JsDecode}, "hello \xe4\xbd\xff world"},                 // JsDecode should not change binary content
		{"hello \xFF\xFF\xFF\xFF\xFF world", []Transformation{JsDecode}, "hello \xFF\xFF\xFF\xFF\xFF world"}, // JsDecode should not change binary content

		{"hello \x00 world", []Transformation{RemoveNulls}, "hello  world"},

		{"hello   world", []Transformation{CompressWhitespace}, "hello world"},
		{"hello   \xa0\xa0\xa0\xa0  world", []Transformation{CompressWhitespace}, "hello world"},
		{"hello   \f\t\n\r\v\xa0  world", []Transformation{CompressWhitespace}, "hello world"},
		{"hello\xa0world", []Transformation{CompressWhitespace}, "hello world"},
		{"hello\xa0\xa0\xa0world", []Transformation{CompressWhitespace}, "hello world"},

		{"helloworld", []Transformation{Length}, "10"},

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
		newMultiRegexEngineMockFunc: func(mm []waf.MultiRegexEnginePattern) waf.MultiRegexEngine {
			return &mockMultiRegexEngine{
				scanMockFunc: func(input []byte) []waf.MultiRegexEngineMatch {
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
		rules := []Statement{&Rule{ID: 100, Items: []RuleItem{{Predicate: RulePredicate{Targets: []Target{{Name: test.target}}, Op: Rx, Val: "abc"}, Transformations: test.inputTransformations}}}}
		req := &mockWafHTTPRequest{uri: test.inputURI}
		rs, err1 := rsf.NewReqScanner(rules)
		s, _ := rs.NewScratchSpace()
		rse := rs.NewReqScannerEvaluation(s)

		// Act
		_, err2 := rse.ScanHeaders(req)

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
