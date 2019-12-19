package ast

import (
	"bytes"
	"strconv"
)

// Equal evaluates whether two Values are equivalent. Multiple string tokens on one side can correspond to a single string token on the other side.
func (v Value) Equal(other Value) bool {
	// A two-pointer algorithm to compare values.
	// This is non-trivial, because multiple string tokens on one side could correspond to a single string token on the other side.

	// Handle empty values
	if len(v) == 0 && len(other) == 0 {
		// Both sides are just empty values
		return true
	} else if len(v) == 0 || len(other) == 0 {
		// One side is empty. Does the other side just have empty string tokens?
		nonEmptySide := v
		if len(v) == 0 {
			nonEmptySide = other
		}

		for _, t := range nonEmptySide {
			if s, ok := t.(StringToken); ok {
				if len(s) != 0 {
					return false
				}
			} else {
				return false
			}
		}

		return true
	}

	a := v
	b := other
	var aPos, bPos int
	var aRemainder, bRemainder []byte
	for {
		switch ta := a[aPos].(type) {

		case IntToken:
			tb, ok := b[bPos].(IntToken)
			if !ok || ta != tb {
				return false
			}
			aPos++
			bPos++

		case MacroToken:
			tb, ok := b[bPos].(MacroToken)
			if !ok || ta != tb {
				return false
			}
			aPos++
			bPos++

		case StringToken:
			tb, ok := b[bPos].(StringToken)
			if !ok {
				return false
			}

			// Continue consuming any remainder.
			if len(aRemainder) > 0 {
				ta = aRemainder
			}
			if len(bRemainder) > 0 {
				tb = bRemainder
			}

			// Get the smallest length of the two sides.
			n := len(ta)
			if len(tb) < n {
				n = len(tb)
			}

			// Slice to the smallest length, and update new remainders.
			aRemainder = []byte{}
			if len(ta) > n {
				aRemainder = ta[n:]
			}
			ta = ta[:n]
			bRemainder = []byte{}
			if len(tb) > n {
				bRemainder = tb[n:]
			}
			tb = tb[:n]

			// Do actual comparison.
			if bytes.Compare(ta, tb) != 0 {
				return false
			}

			// Move pointers forward.
			if len(aRemainder) == 0 {
				aPos++
			}
			if len(bRemainder) == 0 {
				bPos++
			}

		case ValidateByteRangeToken:
			tb, ok := b[bPos].(ValidateByteRangeToken)
			if !ok || ta != tb {
				return false
			}
			aPos++
			bPos++

		default:
			// If this happens, there is a serious programming error.
			panic("unsupported type")

		}

		// Did either reach the end without the other reaching the end?
		if (aPos == len(a) && bPos != len(b)) || (aPos != len(a) && bPos == len(b)) {
			return false
		}

		// Did both reach the end?
		if aPos == len(a) && bPos == len(b) {
			return true
		}
	}
}

// Bytes flattens a Value into a []byte.
func (v Value) Bytes() []byte {
	// Shortcut to avoid allocating a bytes.Buffer if this is just a simple single token.
	if len(v) == 1 {
		switch token := v[0].(type) {

		case StringToken:
			return token

		case MacroToken:
			return nil // Seems better to omit unexpanded macro-tokens. So we don't do anything in this case.

		}
	}

	var buf bytes.Buffer
	for _, token := range v {
		switch token := token.(type) {

		case IntToken:
			buf.WriteString(strconv.Itoa(int(token)))

		case StringToken:
			buf.WriteString(string(token))

		case MacroToken:
			// Seems better to omit unexpanded macro-tokens. So we don't do anything in this case.

		}
	}

	return buf.Bytes()
}

// String flattens a Value into a string.
func (v Value) String() string {
	// Shortcut to avoid allocating a bytes.Buffer if this is just a simple single token.
	if len(v) == 1 {
		if n, ok := v[0].(IntToken); ok {
			return strconv.Itoa(int(n))
		}
	}

	return string(v.Bytes())
}

// Int gets the Value as an integer if it contains just a single integer value.
func (v Value) Int() (n int, ok bool) {
	if len(v) == 1 {
		if n, ok := v[0].(IntToken); ok {
			return int(n), ok
		}
	}
	return 0, false
}

// HasMacros returns whether the Value contains macros.
func (v Value) HasMacros() bool {
	for _, t := range v {
		if _, ok := t.(MacroToken); ok {
			return true
		}
	}
	return false
}
