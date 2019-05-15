package secrule

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// Unit tests that know the internals of ruleParserImpl. More "white box" than ruleparsing_test.go.

func TestFindConsume(t *testing.T) {
	// Arrange
	p := &ruleParserImpl{}
	type testcase struct {
		r             *regexp.Regexp
		testVal       string
		expectedMatch string
		expectedRest  string
	}
	tests := []testcase{
		testcase{regexp.MustCompile(`^abc`), `abcxyz`, `abc`, `xyz`},
		testcase{regexp.MustCompile(`^abc`), `xyzabcxyz`, ``, `xyzabcxyz`},
		testcase{regexp.MustCompile(`abc`), `xyzabcdef`, `abc`, `def`},
	}

	// Act and assert
	var b strings.Builder
	for _, test := range tests {
		match, rest := p.findConsume(test.r, test.testVal)

		if match != test.expectedMatch {
			fmt.Fprintf(&b, "Wrong match: %s. Tested input: %s\n", test.expectedMatch, test.testVal)
		}

		if rest != test.expectedRest {
			fmt.Fprintf(&b, "Wrong match: %s. Tested input: %s\n", test.expectedRest, test.testVal)
		}
	}

	if b.Len() > 0 {
		t.Fatalf("%s", b.String())
	}
}

func TestNextArgSimple(t *testing.T) {
	// Arrange
	p := &ruleParserImpl{}

	// Act
	arg, rest := p.nextArg("hello world")

	// Assert
	if arg != "hello" {
		t.Fatalf("Unexpected arg: %s", arg)
	}

	if rest != " world" {
		t.Fatalf("Unexpected rest: %s", arg)
	}
}

func TestNextArgDoubleQuoted(t *testing.T) {
	// Arrange
	p := &ruleParserImpl{}

	// Act
	arg, rest := p.nextArg(`"hello '\" world" something`)

	// Assert
	if arg != `hello '" world` {
		t.Fatalf("Unexpected arg: %s", arg)
	}

	if rest != " something" {
		t.Fatalf("Unexpected rest: %s", arg)
	}
}

func TestNextArgSingleQuoted(t *testing.T) {
	// Arrange
	p := &ruleParserImpl{}

	// Act
	arg, rest := p.nextArg(`'hello \'" world' something`)

	// Assert
	if arg != `hello '" world` {
		t.Fatalf("Unexpected arg: %s", arg)
	}

	if rest != " something" {
		t.Fatalf("Unexpected rest: %s", arg)
	}
}

func TestNextStatement1(t *testing.T) {
	// Arrange
	p := &ruleParserImpl{}
	input := `
		SecRule ARGS "1=1" "deny,msg:'SQL Injection Attack',id:'950901'"
		SecRule ARGS "<script>" "deny,msg:'XSS Attack',id:'950902'"
	`
	lineNumber := 1

	// Act
	stmt, _ := p.nextStatement(input, &lineNumber)

	// Assert
	expected := `SecRule ARGS "1=1" "deny,msg:'SQL Injection Attack',id:'950901'"`
	if stmt != expected {
		t.Fatalf("Unexpected statement. Actual: %s. Expected: %s", stmt, expected)
	}
}

func TestNextStatement2(t *testing.T) {
	// Arrange
	p := &ruleParserImpl{}
	input := `
		SecRule ARGS "1=1" "deny,msg:'SQL Injection Attack',id:'950901'"
		SecRule ARGS "<script>" "deny,msg:'XSS Attack',id:'950902'"
	`
	lineNumber := 1

	// Act
	stmt, rest := p.nextStatement(input, &lineNumber)
	stmt, rest = p.nextStatement(rest, &lineNumber)

	// Assert
	if stmt != `SecRule ARGS "<script>" "deny,msg:'XSS Attack',id:'950902'"` {
		t.Fatalf("Unexpected statement returned: %s", stmt)
	}
}

func TestNextStatementMultiline1(t *testing.T) {

	// Arrange
	p := &ruleParserImpl{}
	input := "SecRule \"ARGS| \\\nARGS_NAMES\" \"<script>\" \"id:'950902'\""
	lineNumber := 1

	// Act
	stmt, _ := p.nextStatement(input, &lineNumber)

	// Assert
	var expected = input
	if stmt != expected {
		t.Fatalf("Unexpected statement returned: %s", stmt)
	}
}

func TestNextStatementMultiline2(t *testing.T) {
	// Arrange
	p := &ruleParserImpl{}
	input := `
		SecRule ARGS "1=1" "deny,msg:'SQL Injection Attack',id:'950901'"
		SecRule ARGS \
			"<script>" \
			"deny,msg:'XSS Attack',id:'950902'"
		SecRule ARGS "2=2" "deny,msg:'SQL Injection Attack',id:'950903'"
	`
	lineNumber := 1

	// Act
	stmt, rest := p.nextStatement(input, &lineNumber)
	stmt, rest = p.nextStatement(rest, &lineNumber)

	// Assert
	var expected = "SecRule ARGS \\\n\"<script>\" \\\n\"deny,msg:'XSS Attack',id:'950902'\""
	if stmt != expected {
		t.Fatalf("Unexpected statement returned: %s", stmt)
	}
}

func TestNextStatementEnd(t *testing.T) {
	// Arrange
	p := &ruleParserImpl{}
	input := `
		SecRule ARGS "1=1" "deny,msg:'SQL Injection Attack',id:'950901'"
		SecRule ARGS "<script>" "deny,msg:'XSS Attack',id:'950902'"
	`
	lineNumber := 1

	// Act
	stmt, rest := p.nextStatement(input, &lineNumber)
	stmt, rest = p.nextStatement(rest, &lineNumber)
	stmt, rest = p.nextStatement(rest, &lineNumber)

	// Assert
	if stmt != "" {
		t.Fatalf("Unexpected statement returned: %s", stmt)
	}
}

func TestParseActionKeyValue(t *testing.T) {
	// Arrange
	p := &ruleParserImpl{}
	type testcase struct {
		input       string
		expectedKey string
		expectedVal string
	}
	tests := []testcase{
		testcase{`id:950902`, `id`, `950902`},
		testcase{`id:'950902'`, `id`, `950902`},
		testcase{`deny`, `deny`, ``},
	}

	// Act and assert
	var b strings.Builder
	for _, test := range tests {
		k, v := p.parseActionKeyValue(test.input)

		if k != test.expectedKey {
			fmt.Fprintf(&b, "Wrong key: %s. Tested input: %s\n", k, test.input)
		}

		if v != test.expectedVal {
			fmt.Fprintf(&b, "Wrong val: %s. Tested input: %s\n", v, test.input)
		}
	}

	if b.Len() > 0 {
		t.Fatalf("%s", b.String())
	}
}
