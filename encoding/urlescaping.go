package encoding

import (
	"bytes"
	"strings"
)

// IsValidURLEncoding checks whether the given string contains all valid URL-encoded escapes.
func IsValidURLEncoding(content string) bool {
	type validateURLEncodingState int
	const (
		_ validateURLEncodingState = iota
		notInEscape
		char1InEscape // This means we've have so far seen something like %
		char2InEscape // This means we've have so far seen something like %2
	)
	state := notInEscape

	for i := 0; i < len(content); i++ {
		c := content[i]
		switch state {
		case notInEscape:
			if c == '%' {
				state = char1InEscape
			}
		case char1InEscape:
			if isHexChar(c) {
				state = char2InEscape
			} else {
				return false
			}
		case char2InEscape:
			if isHexChar(c) {
				state = notInEscape
			} else {
				return false
			}
		}
	}
	if state != notInEscape {
		return false
	}

	return true
}

// WeakURLUnescape attempts to URL-unescape, but if there are any values that could not be URL-unescaped, they will be left as is. Needed for ModSecurity alignment.
func WeakURLUnescape(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}

	var buf bytes.Buffer
	buf.Grow(len(s)) // The unescaped version should be smaller than the escaped, so this pessimistic initial size should avoid making bytes.Buffer having to reallocate.

	// States for the state machine below
	type urlUnescapeState int
	const (
		_ urlUnescapeState = iota
		notInEscape
		char1InEscape // This means we've have so far seen something like %
		char2InEscape // This means we've have so far seen something like %2
	)
	state := notInEscape

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch state {
		case notInEscape:
			if c == '%' {
				state = char1InEscape
			} else if c == '+' {
				buf.WriteByte(' ')
			} else {
				buf.WriteByte(c)
			}
		case char1InEscape:
			if isHexChar(c) {
				state = char2InEscape
			} else {
				// This was not valid URL encoding, so we will just leave the bytes as is.
				buf.WriteByte(s[i-1])
				buf.WriteByte(s[i])
				state = notInEscape
			}
		case char2InEscape:
			if isHexChar(c) {
				buf.WriteByte(unhex(s[i-1])<<4 | unhex(s[i]))
				state = notInEscape
			} else {
				// This was not valid URL encoding, so we will just leave the bytes as is.
				buf.WriteByte(s[i-2])
				buf.WriteByte(s[i-1])
				buf.WriteByte(s[i])
				state = notInEscape
			}
		}
	}

	// Did the string end with an unfinished escape sequence?
	if state == char1InEscape {
		buf.WriteByte(s[len(s)-1])
	} else if state == char2InEscape {
		buf.WriteByte(s[len(s)-2])
		buf.WriteByte(s[len(s)-1])
	}

	return buf.String()
}

func isHexChar(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// Copied from Go's standard library net/url/url.go.
func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}
