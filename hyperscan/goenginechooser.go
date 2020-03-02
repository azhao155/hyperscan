package hyperscan

import (
	"bytes"
	"fmt"
	"regexp"

	"rsc.io/binaryregexp"
)

type goRegexpFacade struct {
	goregexp    *regexp.Regexp
	goregexpBin *binaryregexp.Regexp
}

func compileRegexpFacade(expr string) (g *goRegexpFacade, err error) {
	hasHexEscapedBytes := containsHexEscapedBytes(expr)

	// If there are any non-printable characters, then convert them into the \x00 representation
	var b bytes.Buffer
	for i := 0; i < len(expr); i++ {
		// ' ' is the lowest value printable ASCII char, and '~' is the highest
		if ' ' <= expr[i] && expr[i] <= '~' {
			b.WriteByte(expr[i])
		} else {
			fmt.Fprintf(&b, "\\x%02X", expr[i])
			hasHexEscapedBytes = true
		}
	}
	expr = b.String()

	// Default to using the built in Go regexp engine, but fall back to Russ Cox's fork which allows searching for binary content.
	if !hasHexEscapedBytes {
		var r *regexp.Regexp
		r, err = regexp.Compile(expr)
		if err != nil {
			err = fmt.Errorf("failed to compile Go regexp pattern %v. Error was: %v", expr, err)
			return
		}

		g = &goRegexpFacade{goregexp: r}
	} else {
		var r *binaryregexp.Regexp
		r, err = binaryregexp.Compile(expr)
		if err != nil {
			err = fmt.Errorf("failed to compile Go regexp pattern %v using binary regexp engine. Error was: %v", expr, err)
			return
		}

		g = &goRegexpFacade{goregexpBin: r}
	}

	return
}

func (g *goRegexpFacade) FindSubmatchIndex(b []byte) []int {
	if g.goregexp != nil {
		return g.goregexp.FindSubmatchIndex(b)
	}
	return g.goregexpBin.FindSubmatchIndex(b)
}

var hexEscapeRegexp = regexp.MustCompile(`((^|[^\\])(\\\\)*)\\x([0-9a-fA-F]{2})`)

func containsHexEscapedBytes(s string) bool {
	return hexEscapeRegexp.MatchString(s)
}
