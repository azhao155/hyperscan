package encoding

import (
	"fmt"
	"strings"
	"testing"
)

func TestWeakURLUnescape(t *testing.T) {
	// Arrange
	type testcase struct {
		inputVal string
		expected string
	}
	tests := []testcase{
		{`hello%20world`, `hello world`},
		{`hello%ggworld`, `hello%ggworld`},
		{`hello%20`, `hello `},
		{`hello%2`, `hello%2`},
		{`hello%`, `hello%`},
		{`%20`, ` `},
		{`%2`, `%2`},
		{`%`, `%`},
		{``, ``},
		{`%00`, "\x00"},
		{`x%6ax`, `xjx`},
		{`x%6Ax`, `xjx`},
	}

	// Act and assert
	var b strings.Builder
	for i, test := range tests {
		// Act
		s := WeakURLUnescape(test.inputVal)

		// Assert
		if s != test.expected {
			fmt.Fprintf(&b, "Test %v, input %v. Expected: %v. Actual: %v\n", i+1, test.inputVal, test.expected, s)
		}
	}

	if b.Len() > 0 {
		t.Fatalf("\n%s", b.String())
	}
}

func TestIsValidURLEncoding(t *testing.T) {
	// Arrange
	type testcase struct {
		inputVal string
		expected bool
	}
	tests := []testcase{
		{`hello%20world`, true},
		{`hello%ggworld`, false},
		{`hello%20`, true},
		{`hello%2`, false},
		{`hello%`, false},
		{`%20`, true},
		{`%2`, false},
		{`%`, false},
		{``, true},
		{`%00`, true},
		{`x%6ax`, true},
		{`x%6Ax`, true},
	}

	// Act and assert
	var b strings.Builder
	for i, test := range tests {
		// Act
		s := IsValidURLEncoding(test.inputVal)

		// Assert
		if s != test.expected {
			fmt.Fprintf(&b, "Test %v, input %v. Expected: %v. Actual: %v\n", i+1, test.inputVal, test.expected, s)
		}
	}

	if b.Len() > 0 {
		t.Fatalf("\n%s", b.String())
	}
}
