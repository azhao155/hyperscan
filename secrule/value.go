package secrule

import (
	"bytes"
	"strconv"
	"strings"
)

func (v Value) expandMacros(env environment) (output Value) {
	output = make(Value, 0, len(v)) // Output will contain at max the same number of tokens as input.

	for _, token := range v {
		// Replace with value from env if macro-token.
		if mt, ok := token.(MacroToken); ok {
			if strings.EqualFold(string(mt), "matched_var") {
				output = append(output, StringToken(env.matchedVar))
				continue
			}

			if strings.EqualFold(string(mt), "matched_var_name") {
				output = append(output, StringToken(env.matchedVarName))
				continue
			}

			if strings.EqualFold(string(mt), "request_line") {
				output = append(output, StringToken(env.requestLine))
				continue
			}

			if strings.EqualFold(string(mt), "request_headers.host") {
				output = append(output, StringToken(env.hostHeader))
				continue
			}

			// Tx-variables
			if len(mt) > 3 && strings.EqualFold(string(mt)[0:3], "tx.") {
				var ok bool
				o, ok := env.get(string(mt))
				if !ok {
					continue
				}

				switch o := o.(type) {
				case *integerObject:
					output = append(output, IntToken(o.Value))
				case *stringObject:
					output = append(output, StringToken(o.ToString()))
				}

				continue
			}
		}

		// This was not a macro token, so just keep it as is.
		output = append(output, token)
	}

	return
}

func (v Value) equal(other Value) bool {
	// A two-pointer algorithm to compare values.
	// This is non-trivial, because multiple string tokens on one side could correspond to a single string token on the other side.

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

func (v Value) bytes() []byte {
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

func (v Value) string() string {
	return string(v.bytes())
}
