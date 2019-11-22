package secrule

import (
	"fmt"
	"strings"
	"testing"
)

func TestValueEqual(t *testing.T) {
	// Arrange
	type testCase struct {
		a        Value
		b        Value
		expected bool
	}
	tests := []testCase{
		{Value{IntToken(123)}, Value{IntToken(123)}, true},
		{Value{IntToken(123)}, Value{IntToken(321)}, false},
		{Value{IntToken(123)}, Value{IntToken(12), IntToken(3)}, false},
		{Value{IntToken(12), IntToken(3)}, Value{IntToken(123)}, false},

		{Value{StringToken("aaabbb")}, Value{StringToken("aaabbb")}, true},
		{Value{StringToken("aaabbb")}, Value{StringToken("aaaccc")}, false},
		{Value{StringToken("aaabbb")}, Value{StringToken("aaabbb"), StringToken("ccc")}, false},
		{Value{StringToken("aaabbb"), StringToken("ccc")}, Value{StringToken("aaabbb")}, false},
		{Value{StringToken("aaabbb")}, Value{StringToken("aaa"), StringToken("bbb")}, true},
		{Value{StringToken("aaa"), StringToken("bbb")}, Value{StringToken("aaabbb")}, true},
		{Value{StringToken("aaabbb"), StringToken("ccc")}, Value{StringToken("aaa"), StringToken("bbbccc")}, true},
		{Value{StringToken("aaa"), IntToken(123), StringToken("bbb")}, Value{StringToken("aaa"), IntToken(123), StringToken("bbb")}, true},
		{Value{StringToken("aaa"), IntToken(123), StringToken("bbb")}, Value{StringToken("aaa"), IntToken(321), StringToken("bbb")}, false},
		{Value{StringToken("aaa"), IntToken(123), StringToken("bbb")}, Value{StringToken("aaa"), IntToken(123), StringToken("ccc")}, false},

		{Value{MacroToken("xxx")}, Value{MacroToken("xxx")}, true},
		{Value{MacroToken("xxx")}, Value{MacroToken("yyy")}, false},
		{Value{MacroToken("xxxyyy")}, Value{MacroToken("xxx"), MacroToken("yyy")}, false},
		{Value{MacroToken("xxx"), MacroToken("yyy")}, Value{MacroToken("xxxyyy")}, false},

		{Value{StringToken("aaa"), StringToken("bbb"), IntToken(123), MacroToken("xxx")}, Value{StringToken("aaabbb"), IntToken(123), MacroToken("xxx")}, true},
	}

	var b strings.Builder
	for i, test := range tests {
		// Act and assert
		r := test.a.equal(test.b)
		if r != test.expected {
			fmt.Fprintf(&b, "Got unexpected result on item %v: %v\n", i, r)
			continue
		}
	}

	if b.Len() > 0 {
		t.Fatalf("\n%s", b.String())
	}
}
