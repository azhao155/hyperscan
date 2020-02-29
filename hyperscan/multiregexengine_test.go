package hyperscan

import (
	"strings"
	"testing"
)

func TestContainsHexEscapedBytes(t *testing.T) {
	// Arrange
	type testcase struct {
		rx                 string
		hasHexEscapedBytes bool
	}
	tests := []testcase{
		{`xyz\xaaxyz`, true},
		{`xyz\xaAxyz`, true},
		{`xyz\xAaxyz`, true},
		{`xyz\x00xyz`, true},
		{`xyz\X00xyz`, false},
		{`xyz\\x00xyz`, false},
		{`xyz\\\x00xyz`, true},
		{`\\\x00xyz`, true},
		{`\\x00xyz`, false},
		{`\\\\x00xyz`, false},
		{`\\\\\x00xyz`, true},
	}

	var b strings.Builder
	for _, test := range tests {
		// Act and assert
		if containsHexEscapedBytes(test.rx) != test.hasHexEscapedBytes {
			t.Fatalf("Got unexpected containsHexEscapedBytes(test.rx) for %v", test.rx)
		}
	}

	if b.Len() > 0 {
		t.Fatalf("%s", b.String())
	}
}
