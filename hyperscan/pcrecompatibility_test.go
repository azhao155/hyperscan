package hyperscan

import (
	"azwaf/waf"
	"fmt"
	"strings"
	"testing"
)

func TestRemovePcrePossessiveQuantifier(t *testing.T) {
	// Arrange
	type testcase struct {
		input    string
		expected string
	}
	tests := []testcase{
		{`a++`, `a+`},
		{`a\++`, `a\++`},
		{`\++`, `\++`},
		{`\\++`, `\\+`},
		{`\\\++`, `\\\++`},
		{`\\\\++`, `\\\\+`},
		{`\\\\\++`, `\\\\\++`},
		{`xa++a++x`, `xa+a+x`},
		{`xa\++a++x`, `xa\++a+x`},
		{`xa\++a\++x`, `xa\++a\++x`},
		{
			`(?i:([\s'"\(\)]*?)([\d\w]++)([\s'"\(\)]*?)(?:(?:=|<=>|r?like|sounds\s+like|regexp)([\s'"\(\)]*?)\2|(?:!=|<=|>=|<>|<|>|\^|is\s+not|not\s+like|not\s+regexp)([\s'"\(\)]*?)(?!\2)([\d\w]+)))`,
			`(?i:([\s'"\(\)]*?)([\d\w]+)([\s'"\(\)]*?)(?:(?:=|<=>|r?like|sounds\s+like|regexp)([\s'"\(\)]*?)\2|(?:!=|<=|>=|<>|<|>|\^|is\s+not|not\s+like|not\s+regexp)([\s'"\(\)]*?)(?!\2)([\d\w]+)))`,
		},
		{`a*+`, `a*`},
		{`a\*+`, `a\*+`},
		{`\*+`, `\*+`},
		{`\\*+`, `\\*`},
		{`\\\*+`, `\\\*+`},
		{`\\\\*+`, `\\\\*`},
		{`\\\\\*+`, `\\\\\*+`},
		{`xa*+a*+x`, `xa*a*x`},
		{`xa\*+a*+x`, `xa\*+a*x`},
		{`xa\*+a\*+x`, `xa\*+a\*+x`},
		{`a?+`, `a?`},
		{`a\?+`, `a\?+`},
		{`\?+`, `\?+`},
		{`\\?+`, `\\?`},
		{`\\\?+`, `\\\?+`},
		{`\\\\?+`, `\\\\?`},
		{`\\\\\?+`, `\\\\\?+`},
		{`xa?+a?+x`, `xa?a?x`},
		{`xa\?+a?+x`, `xa\?+a?x`},
		{`xa\?+a\?+x`, `xa\?+a\?+x`},
		{`a{2,5}+`, `a{2,5}`},
		{`a\{2,5}+`, `a\{2,5}+`},
		{`\{2,5}+`, `\{2,5}+`},
		{`\\{2,5}+`, `\\{2,5}`},
		{`\\\{2,5}+`, `\\\{2,5}+`},
		{`\\\\{2,5}+`, `\\\\{2,5}`},
		{`\\\\\{2,5}+`, `\\\\\{2,5}+`},
		{`xa{2,5}+a{2,5}+x`, `xa{2,5}a{2,5}x`},
		{`xa\{2,5}+a{2,5}+x`, `xa\{2,5}+a{2,5}x`},
		{`xa\{2,5}+a\{2,5}+x`, `xa\{2,5}+a\{2,5}+x`},
		{`a{2,}+`, `a{2,}`},
		{`a\{2,}+`, `a\{2,}+`},
		{`\{2,}+`, `\{2,}+`},
		{`\\{2,}+`, `\\{2,}`},
		{`\\\{2,}+`, `\\\{2,}+`},
		{`\\\\{2,}+`, `\\\\{2,}`},
		{`\\\\\{2,}+`, `\\\\\{2,}+`},
		{`a{2}+`, `a{2}`},
		{`a\{2}+`, `a\{2}+`},
		{`\{2}+`, `\{2}+`},
		{`\\{2}+`, `\\{2}`},
		{`\\\{2}+`, `\\\{2}+`},
		{`\\\\{2}+`, `\\\\{2}`},
		{`\\\\\{2}+`, `\\\\\{2}+`},
	}

	// Act and assert
	var b strings.Builder
	for i, test := range tests {
		r := removePcrePossessiveQuantifier(test.input)

		if r != test.expected {
			fmt.Fprintf(&b, "Unexpected result %d. Expected: %s. Actual: %s.\n", i, test.expected, r)
		}
	}

	if b.Len() > 0 {
		t.Fatalf("%s", b.String())
	}
}

func TestBackrefReplacements(t *testing.T) {
	// Arrange
	type testcase struct {
		input                            string
		expectedNewRegex                 string
		expectedLookbehindReferenceToID  int
		expectedShouldBeEqualGroupIDs    []int
		expectedShouldBeNotEqualGroupIDs []int
	}
	tests := []testcase{
		// Simple backrefs
		{`\b(abc\d+)\b \b\1\b (xyz)`, `\b(abc\d+)\b \b(abc\d+)\b (xyz)`, 1, []int{2}, []int{}},
		{`\b(abc\d+)\b def \b\1\b (xyz)`, `\b(abc\d+)\b def \b(abc\d+)\b (xyz)`, 1, []int{2}, []int{}},

		// Backrefs inside a negative lookahead followed by a group equivalent to the lookbehind.
		{`\b(abc\d+)\b (?!\b\1\b)(abc\d+)`, `\b(abc\d+)\b (\babc\d+\b)`, 1, []int{}, []int{2}},
		{`\b(abc\d+)\b (?!\b\1\b)(abc\d+) (xyz)`, `\b(abc\d+)\b (\babc\d+\b) (xyz)`, 1, []int{}, []int{2}},
		{`\b(abc\d+)\b \b\1\b xyz(?!\b\1\b)(abc\d+) (ghi)`, `\b(abc\d+)\b \b(abc\d+)\b xyz(\babc\d+\b) (ghi)`, 1, []int{2}, []int{3}},
		{`\b(abc\d+)\b \b\1\b (xyz)(?!\b\1\b)(abc\d+) (ghi)`, `\b(abc\d+)\b \b(abc\d+)\b (xyz)(\babc\d+\b) (ghi)`, 1, []int{2}, []int{4}},
		{`\b(abc\d+)\b (?!\b\1\b)abc\d+ xyz`, `\b(abc\d+)\b (\babc\d+\b) xyz`, 1, []int{}, []int{2}},

		// Backrefs inside a negative lookahead, but without being followed by a group equivalent to the lookbehind. This a negative test for a scenario we don't support.
		{`\b(abc\d+)\b (?!\b\1\b)(xyz)`, `\b(abc\d+)\b (?!\b(abc\d+)\b)(xyz)`, 1, []int{2}, []int{}},

		// This test is equivalent to rule 942130 in CRS 3.0
		{
			`(?i:([\s'"` + "`" + `\(\)]*?)\b([\d\w]++)\b([\s'"` + "`" + `\(\)]*?)(?:(?:=|<=>|r?like|sounds\s+like|regexp)([\s'"` + "`" + `\(\)]*?)\b\2\b|(?:!=|<=|>=|<>|<|>|\^|is\s+not|not\s+like|not\s+regexp)([\s'"` + "`" + `\(\)]*?)(?!\b\2\b)([\d\w]+)))`,
			`(?i:([\s'"` + "`" + `\(\)]*?)\b([\d\w]+)\b([\s'"` + "`" + `\(\)]*?)(?:(?:=|<=>|r?like|sounds\s+like|regexp)([\s'"` + "`" + `\(\)]*?)\b([\d\w]+)\b|(?:!=|<=|>=|<>|<|>|\^|is\s+not|not\s+like|not\s+regexp)([\s'"` + "`" + `\(\)]*?)(\b[\d\w]+\b)))`,
			2,
			[]int{5},
			[]int{7},
		},

		// This test is equivalent to rule 942130 in CRS 3.2
		{
			`(?i:[\s'"` + "`" + `()]*?\b([\d\w]++)\b[\s'"` + "`" + `()]*?(?:<(?:=(?:[\s'"` + "`" + `()]*?(?!\b\1\b)[\d\w]+|>[\s'"` + "`" + `()]*?(?:\b\1\b))|>?[\s'"` + "`" + `()]*?(?!\b\1\b)[\d\w]+)|(?:not\s+(?:regexp|like)|is\s+not|>=?|!=|\^)[\s'"` + "`" + `()]*?(?!\b\1\b)[\d\w]+|(?:(?:sounds\s+)?like|r(?:egexp|like)|=)[\s'"` + "`" + `()]*?(?:\b\1\b)))`,
			`(?i:[\s'"` + "`" + `()]*?\b([\d\w]+)\b[\s'"` + "`" + `()]*?(?:<(?:=(?:[\s'"` + "`" + `()]*?(\b[\d\w]+\b)|>[\s'"` + "`" + `()]*?(?:\b([\d\w]+)\b))|>?[\s'"` + "`" + `()]*?(\b[\d\w]+\b))|(?:not\s+(?:regexp|like)|is\s+not|>=?|!=|\^)[\s'"` + "`" + `()]*?(\b[\d\w]+\b)|(?:(?:sounds\s+)?like|r(?:egexp|like)|=)[\s'"` + "`" + `()]*?(?:\b([\d\w]+)\b)))`,
			1,
			[]int{3, 6},
			[]int{2, 4, 5},
		},
	}

	// Act and assert
	var b strings.Builder
	for i, test := range tests {
		hasBackref, r, err := newRegexWithBackref(test.input)

		if err != nil {
			fmt.Fprintf(&b, "Unexpected error %v: %v\n", i, err)
		}

		if !hasBackref {
			fmt.Fprintf(&b, "Unexpected hasBackref %v\n", i)
		}

		if r.newRegex != test.expectedNewRegex {
			fmt.Fprintf(&b, "Unexpected result %v for newRegex. Expected: %v. Actual: %v.\n", i, test.expectedNewRegex, r.newRegex)
		}

		if r.lookbehindReferenceToID != test.expectedLookbehindReferenceToID {
			fmt.Fprintf(&b, "Unexpected result %v for lookbehindReferenceToID. Expected: %v. Actual: %v.\n", i, test.expectedLookbehindReferenceToID, r.lookbehindReferenceToID)
		}

		if fmt.Sprintf("%v", r.shouldBeEqualGroupIDs) != fmt.Sprintf("%v", test.expectedShouldBeEqualGroupIDs) {
			fmt.Fprintf(&b, "Unexpected result %v for shouldBeEqualGroupIDs. Expected: %v. Actual: %v.\n", i, test.expectedShouldBeEqualGroupIDs, r.shouldBeEqualGroupIDs)
		}

		if fmt.Sprintf("%v", r.shouldBeNotEqualGroupIDs) != fmt.Sprintf("%v", test.expectedShouldBeNotEqualGroupIDs) {
			fmt.Fprintf(&b, "Unexpected result %v for shouldBeNotEqualGroupIDs. Expected: %v. Actual: %v.\n", i, test.expectedShouldBeNotEqualGroupIDs, r.shouldBeNotEqualGroupIDs)
		}

	}

	if b.Len() > 0 {
		t.Fatalf("%s", b.String())
	}
}

func TestBackrefErrors(t *testing.T) {
	// Arrange
	type testcase struct {
		input         string
		expectedError string
	}
	tests := []testcase{
		{`(abc`, `incomplete group`},
		{`\1(abc\d+)`, `backreference attempted to reference group 1, but only backreference to previous groups is supported`},
		{`(abc\d+\1)`, `backreference in group 1 attempted to reference group 1, but circular backreferences are not support`},
		{`(abc\d+\0)`, `backreference to group 0 is not supported`},
		{`abc\d+\1`, `backreference attempted to reference group 1, but only backreference to previous groups is supported`},
	}

	// Act and assert
	var b strings.Builder
	for i, test := range tests {
		_, _, err := newRegexWithBackref(test.input)

		if err == nil {
			fmt.Fprintf(&b, "Expected error but got nil for %v\n", i)
			continue
		}

		if err.Error() != test.expectedError {
			fmt.Fprintf(&b, "Unexpected error %v: %v\n", i, err)
		}

	}

	if b.Len() > 0 {
		t.Fatalf("%s", b.String())
	}
}

func TestBackrefHasBackref(t *testing.T) {
	// Arrange
	type testcase struct {
		input              string
		expectedHasBackref bool
	}
	tests := []testcase{
		{`abc`, false},
		{`(abc\d+)\1`, true},
	}

	// Act and assert
	var b strings.Builder
	for i, test := range tests {
		hasBackref, _, _ := newRegexWithBackref(test.input)

		if hasBackref != test.expectedHasBackref {
			fmt.Fprintf(&b, "Unexpected hasBackref %v\n", i)
		}
	}

	if b.Len() > 0 {
		t.Fatalf("%s", b.String())
	}
}

func TestBackrefs(t *testing.T) {
	// Arrange
	type testcase struct {
		testID      int
		rx          string
		input       string
		shouldMatch bool
	}
	tests := []testcase{
		// Simple backrefs
		{100, `\b(abc\d+)\b \b\1\b (xyz)`, `abc123 abc123 xyz`, true},
		{200, `\b(abc\d+)\b def \b\1\b (xyz)`, `abc123 def abc123 xyz`, true},
		{300, `\b(abc\d+)\b \b\1\b \b\1\b (xyz)`, `abc123 abc123 abc123 xyz`, true},
		{310, `\b(a+bc\d+)\b \b\1\b (xyz)`, `aaaabc123 abc123 xyz`, false},
		{320, `\b(a+bc\d+)\b \b\1\b (xyz)`, `abc123 aaaabc123 xyz`, false},

		// Backrefs inside a negative lookahead followed by a group equivalent to the lookbehind.
		{400, `\b(abc\d+)\b (?!\b\1\b)(abc\d+)`, `abc123 abc321`, true},
		{500, `\b(abc\d+)\b (?!\b\1\b)(abc\d+) (xyz)`, `abc123 abc321 xyz`, true},
		{600, `\b(abc\d+)\b \b\1\b xyz (?!\b\1\b)(abc\d+) (ghi)`, `abc123 abc123 xyz abc321 ghi`, true},
		{700, `\b(abc\d+)\b \b\1\b (xyz) (?!\b\1\b)(abc\d+) (ghi)`, `abc123 abc123 xyz abc321 ghi`, true},
		{800, `\b(abc\d+)\b (?!\b\1\b)abc\d+ xyz`, `abc123 abc321 xyz`, true},
		{900, `\b(a+bc\d+)\b (?!\b\1\b)a+bc\d+ xyz`, `aaaabc123 abc123 xyz`, true},
		{1000, `\b(a+bc\d+)\b (?!\b\1\b)a+bc\d+ xyz`, `abc123 aaaabc123 xyz`, true},
		{1100, `\b(abc\d+)\b (?!\b\1\b)abc\d+ xyz`, `abc123333 abc123 xyz`, true},
		{1200, `\b(abc\d+)\b (?!\b\1\b)abc\d+ xyz`, `abc123 abc123333 xyz`, true},

		// One of the components of 942130 in CRS 3.2, with its FTW test.
		{2000, "(?i:[\\s'\\\"`()]*?\\b([\\d\\w]++)\\b[\\s'\\\"`()]*?like[\\s'\\\"`()]*?(?:\\b\\1\\b))", `"1" SOUNDS LIKE "SOUNDS LIKE 1`, true},

		// All of 942130 in CRS 3.2, with its FTW tests.
		{2100, "(?i:(?i:[\\s'\"`()]*?\\b([\\d\\w]++)\\b[\\s'\"`()]*?(?:<(?:=(?:[\\s'\"`()]*?(?!\\b\\1\\b)[\\d\\w]+|>[\\s'\"`()]*?(?:\\b\\1\\b))|>?[\\s'\"`()]*?(?!\\b\\1\\b)[\\d\\w]+)|(?:not\\s+(?:regexp|like)|is\\s+not|>=?|!=|\\^)[\\s'\"`()]*?(?!\\b\\1\\b)[\\d\\w]+|(?:(?:sounds\\s+)?like|r(?:egexp|like)|=)[\\s'\"`()]*?(?:\\b\\1\\b))))", `"1" SOUNDS LIKE "SOUNDS LIKE 1`, true},
	}

	var b strings.Builder
	for _, test := range tests {
		// Act
		patterns := []waf.MultiRegexEnginePattern{
			{ID: 1, Expr: test.rx},
		}
		f := NewMultiRegexEngineFactory(nil)
		m, err := f.NewMultiRegexEngine(patterns)
		if err != nil {
			t.Fatalf("Got unexpected error: %s", err)
		}
		s, err := m.CreateScratchSpace()
		if err != nil {
			t.Fatalf("Got unexpected error: %s", err)
		}
		r, err := m.Scan([]byte(test.input), s)
		if err != nil {
			t.Fatalf("Got unexpected error: %s", err)
		}
		m.Close()

		// Assert
		if len(r) >= 1 != test.shouldMatch {
			fmt.Fprintf(&b, "Got unexpected number of matches for test %v, %v, %v: %d\n", test.testID, test.rx, test.input, len(r))
		}
	}

	if b.Len() > 0 {
		t.Fatalf("\n%s", b.String())
	}
}
