package secrule

import (
	"azwaf/encoding"
	"bytes"
	"fmt"
	"html"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// TODO consider also replacing other kind of unicode spaces
// Explicitly writing out what the SecRule-lang considers whitespaces, as it differs a little from Go Regexp's "\s".
var whitespaceRegex = regexp.MustCompile(`[\x20\x0c\x09\x0a\x0d\x0b]+`) // ' ', \f, \t, \n, \r, \v. (0xa0 is done separately because the regex engine seems to have trouble with it.)

func applyTransformations(s string, tt []Transformation) string {
	// TODO implement a trie for caching already done transformations

	orig := s
	for _, t := range tt {
		// TODO implement all transformations
		switch t {
		case CmdLine:
		case CompressWhitespace:
			if whitespaceRegex.FindStringIndex(s) != nil || strings.Contains(s, "\xa0") {
				s = strings.Replace(s, "\xa0", " ", -1) // The regex engine seems to have trouble with 0xa0, so doing it separately.
				s = whitespaceRegex.ReplaceAllString(s, " ")
			}
		case CSSDecode:
		case HexEncode:
		case HTMLEntityDecode:
			if strings.Contains(s, "&") {
				s = html.UnescapeString(s)
				// TODO ensure this aligns with the intended htmlEntityDecode functionality of SecRule-lang: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#htmlEntityDecode
				// TODO read https://golang.org/pkg/html/#UnescapeString closely. We need to think about if the unicode behaviour here is correct for SecRule-lang.
			}
		case JsDecode:
			s = jsUnescape(s)
		case Length:
			// TODO is this really used? Isn't @ for this? Should we use the type-system to keep this as int here?
			s = strconv.Itoa(len(s))
		case Lowercase:
			s = strings.ToLower(s)
		case None:
			s = orig
		case NormalisePath, NormalizePath:
		case NormalisePathWin, NormalizePathWin:
		case RemoveComments:
		case RemoveNulls:
			if strings.Contains(s, "\x00") {
				s = strings.Replace(s, "\x00", "", -1)
			}
		case RemoveWhitespace:
			if whitespaceRegex.FindStringIndex(s) != nil || strings.Contains(s, "\xa0") {
				s = strings.Replace(s, "\xa0", "", -1) // The regex engine seems to have trouble with 0xa0, so doing it separately.
				s = whitespaceRegex.ReplaceAllString(s, "")
			}
		case ReplaceComments:
		case Sha1:
		case URLDecode, URLDecodeUni:
			s = encoding.WeakURLUnescape(s)
		case Utf8toUnicode:
			s = utf8ToUnicode(s)
		}
	}

	return s
}

// According to the book ModSecurity Handbook, this transformation should convert all UTF-8 characters sequences to Unicode using a %uHHHH syntax.
func utf8ToUnicode(input string) (output string) {
	// Check first if there any UTF-8 sequences before we start doing memory allocations.
	// The range-operator on a string will parse UTF-8 sequences into the rune type.
	hasUtf8 := false
	expectedNewLength := 0
	for _, runeVal := range input {
		if runeVal > 127 && runeVal != utf8.RuneError {
			hasUtf8 = true
			expectedNewLength += 6 // The escaped sequences are 6 bytes and look like this: %u4f60
		} else {
			expectedNewLength++
		}
	}
	if !hasUtf8 {
		return input
	}

	// Pre-allocate a large enough buffer to avoid making bytes.Buffer having to reallocate.
	var buf bytes.Buffer
	buf.Grow(expectedNewLength)

	for i, runeVal := range input {
		if runeVal > 127 && runeVal != utf8.RuneError {
			fmt.Fprintf(&buf, "%%u%04x", runeVal)
		} else {
			buf.WriteByte(input[i])
		}
	}

	output = buf.String()

	return
}

// Javascript unescape.
// Mostly based on https://www.ecma-international.org/ecma-262/6.0/#sec-literals-string-literals
// plus we imitate a little bit of special behaviour like ModSecurity has.
func jsUnescape(input string) string {
	// Don't allocate memory if we know up front that there are no escape sequences in this string.
	if !strings.Contains(input, "\\") {
		return input
	}

	var buf bytes.Buffer
	buf.Grow(len(input)) // The unescaped version should be smaller than the escaped, so this pessimistic initial size should avoid making bytes.Buffer having to reallocate.

	// States for the state machine below
	const (
		_ = iota
		notInEscape
		char1InEscape                  // This means we've have so far seen something like \
		char1InHexEscape               // This means we've have so far seen something like \x
		char2InHexEscape               // This means we've have so far seen something like \xA
		char1InUnicodeHexEscape        // This means we've have so far seen something like \u
		char2InUnicodeHexEscape        // This means we've have so far seen something like \u4
		char3InUnicodeHexEscape        // This means we've have so far seen something like \u4f
		char4InUnicodeHexEscape        // This means we've have so far seen something like \u4f6
		inCurlyBracketUnicodeHexEscape // This means we've have so far seen something like \u{ followed by 0 or more bytes, tracked by escapeStartPos.
		char2InOctalEscape             // This means we've have so far seen something like \0
		char3InOctalEscape             // This means we've have so far seen something like \00
	)
	state := notInEscape
	escapeStartPos := 0

	for i := 0; i < len(input); i++ {
		c := input[i]
		switch state {
		case notInEscape:
			if c == '\\' {
				state = char1InEscape
				escapeStartPos = i
			} else {
				buf.WriteByte(c)
			}
		case char1InEscape:
			switch c {
			case '\'', '"', '\\':
				buf.WriteByte(c)
				state = notInEscape
			case 'b':
				buf.WriteByte('\b')
				state = notInEscape
			case 'f':
				buf.WriteByte('\f')
				state = notInEscape
			case 'n':
				buf.WriteByte('\n')
				state = notInEscape
			case 'r':
				buf.WriteByte('\r')
				state = notInEscape
			case 't':
				buf.WriteByte('\t')
				state = notInEscape
			case 'v':
				buf.WriteByte('\v')
				state = notInEscape
			case 'x':
				state = char1InHexEscape
			case 'u':
				state = char1InUnicodeHexEscape
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				state = char2InOctalEscape
			default:
				buf.WriteByte(c) // Fallback to just writing the input without the \.
				state = notInEscape
			}
		case char1InHexEscape:
			switch c {
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'a', 'B', 'b', 'C', 'c', 'D', 'd', 'E', 'e', 'F', 'f':
				state = char2InHexEscape
			default:
				buf.WriteString(input[i-1 : i+1]) // Fallback to just writing the input without the \.
				state = notInEscape
			}
		case char2InHexEscape:
			switch c {
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'a', 'B', 'b', 'C', 'c', 'D', 'd', 'E', 'e', 'F', 'f':
				b, _ := strconv.ParseInt(input[i-1:i+1], 16, 64)
				buf.WriteByte(byte(b))
				state = notInEscape
			default:
				buf.WriteString(input[i-2 : i+1]) // Fallback to just writing the input without the \.
				state = notInEscape
			}
		case char1InUnicodeHexEscape:
			switch c {
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'a', 'B', 'b', 'C', 'c', 'D', 'd', 'E', 'e', 'F', 'f':
				state = char2InUnicodeHexEscape
			case '{':
				state = inCurlyBracketUnicodeHexEscape
			default:
				buf.WriteString(input[i-1 : i+1]) // Fallback to just writing the input without the \.
				state = notInEscape
			}
		case char2InUnicodeHexEscape:
			switch c {
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'a', 'B', 'b', 'C', 'c', 'D', 'd', 'E', 'e', 'F', 'f':
				state = char3InUnicodeHexEscape
			default:
				buf.WriteString(input[i-2 : i+1])
				state = notInEscape
			}
		case char3InUnicodeHexEscape:
			switch c {
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'a', 'B', 'b', 'C', 'c', 'D', 'd', 'E', 'e', 'F', 'f':
				state = char4InUnicodeHexEscape
			default:
				buf.WriteString(input[i-3 : i+1])
				state = notInEscape
			}
		case char4InUnicodeHexEscape:
			switch c {
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'a', 'B', 'b', 'C', 'c', 'D', 'd', 'E', 'e', 'F', 'f':
				r, _ := strconv.ParseInt(input[i-3:i+1], 16, 64) // No err handling needed, because we know the prior four bytes were hex digits.
				r = unicodeFullWidthToASCII(r)
				buf.WriteRune(rune(r))
				state = notInEscape
			default:
				buf.WriteString(input[i-4 : i+1])
				state = notInEscape
			}
		case inCurlyBracketUnicodeHexEscape:
			switch c {
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'a', 'B', 'b', 'C', 'c', 'D', 'd', 'E', 'e', 'F', 'f':
				// Stay in same state.
			case '}':
				r, err := strconv.ParseInt(input[escapeStartPos+3:i], 16, 64)
				if r > 1114111 || err != nil {
					// Unicode is a 21-bit character set. Max code point is 1114111.
					// Fallback to just writing the input without the \.
					buf.WriteString(input[escapeStartPos+1 : i+1])
				} else {
					r = unicodeFullWidthToASCII(r)
					buf.WriteRune(rune(r))
				}
				state = notInEscape
			default:
				buf.WriteString(input[escapeStartPos+1 : i+1])
				state = notInEscape
			}
		case char2InOctalEscape:
			switch c {
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				state = char3InOctalEscape
			default:
				// Char 2 in the octal escape sequence was not an octal digit.
				// This means the previous byte was the only one in the octal escape sequence.
				// Example of such as sequence: \1
				b, _ := strconv.ParseInt(input[i-1:i], 8, 64) // No err handling needed, because we know the byte was an octal digit.
				buf.WriteByte(byte(b))
				state = notInEscape

				// The byte we have currently arrived at was not part of the octal escape sequence, so we need to deal with it accordingly.
				if c == '\\' {
					state = char1InEscape
				} else {
					buf.WriteByte(c)
				}
			}
		case char3InOctalEscape:
			switch c {
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				// Char 3 in the octal escape sequence was an octal digit.
				// This means we have arrived at the third and final possible digit of the octal escape sequence.
				// Example of such as sequence: \001
				b, _ := strconv.ParseInt(input[i-2:i+1], 8, 64) // No err handling needed, because we know the prior three bytes were octal digits.
				buf.WriteByte(byte(b))
				state = notInEscape
			default:
				// Char 3 in the octal escape sequence was not an octal digit.
				// This means just the previous two bytes was in the octal escape sequence.
				// Example of such as sequence: \01
				b, _ := strconv.ParseInt(input[i-2:i], 8, 64) // No err handling needed, because we know the prior two bytes were octal digits.
				buf.WriteByte(byte(b))
				state = notInEscape

				// The byte we have currently arrived at was not part of the octal escape sequence, so we need to deal with it accordingly.
				if c == '\\' {
					state = char1InEscape
				} else {
					buf.WriteByte(c)
				}
			}
		}
	}

	// Did the string end with an unfinished escape sequence?
	if state != notInEscape {
		switch state {
		case char2InOctalEscape:
			// The last char we read put us in the char2InOctalEscape, meaning it must have been the first and only char in the octal escape sequence.
			// Example of such as sequence: \1
			b, _ := strconv.ParseInt(input[escapeStartPos+1:], 8, 64) // No err handling needed, because we know the byte was an octal digit.
			buf.WriteByte(byte(b))
		case char3InOctalEscape:
			// The last char we read put us in the char3InOctalEscape, meaning it must have been the second char in the octal escape sequence.
			// Example of such as sequence: \01
			b, _ := strconv.ParseInt(input[escapeStartPos+1:], 8, 64) // No err handling needed, because we know the prior two bytes were octal digits.
			buf.WriteByte(byte(b))
		default:
			buf.WriteString(input[escapeStartPos+1:]) // Fallback to just writing the input without the \.
		}
	}

	return buf.String()
}

// ModSecurity has a very special handling of full width characters (ff01 - ff5e). It maps them to the corresponding ASCII characters. We will imitate this.
func unicodeFullWidthToASCII(r int64) int64 {
	if r >= 0xff01 && r <= 0xff5e {
		// The first printable char in ASCII is 0x20, and corresponds to 0xFF00.
		lowestByte := r & 0xff
		r = lowestByte + 0x20
	}
	return r
}

func transformationListEquals(a []Transformation, b []Transformation) bool {
	if len(a) != len(b) {
		return false
	}

	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
