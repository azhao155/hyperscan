package hyperscan

import (
	"regexp"
	"strings"
)

var removePcrePlusPossessiveQuantifierRegex = regexp.MustCompile(`((^|[^\\])(\\\\)*)\+\+`)
var removePcreStarPossessiveQuantifierRegex = regexp.MustCompile(`((^|[^\\])(\\\\)*)\*\+`)
var removePcreQuestionmarkPossessiveQuantifierRegex = regexp.MustCompile(`((^|[^\\])(\\\\)*)\?\+`)
var removePcreRangePossessiveQuantifierRegex = regexp.MustCompile(`((^|[^\\])(\\\\)*)({\d+(,(\d+)?)?})\+`)

// PCRE has the possessive quantifier "++", which is just meant as a hint to not backtrack and thereby increase performance.
// Go regexp does not need this, as it never backtracks anyway. The syntax is invalid in Go regexp. This function removes it from a regex.
func removePcrePossessiveQuantifier(r string) string {
	if strings.Index(r, "++") != -1 {
		r = removePcrePlusPossessiveQuantifierRegex.ReplaceAllString(r, "${1}+")
	}

	if strings.Index(r, "*+") != -1 {
		r = removePcreStarPossessiveQuantifierRegex.ReplaceAllString(r, "${1}*")
	}

	if strings.Index(r, "?+") != -1 {
		r = removePcreQuestionmarkPossessiveQuantifierRegex.ReplaceAllString(r, "${1}?")
	}

	if strings.Index(r, "}+") != -1 {
		r = removePcreRangePossessiveQuantifierRegex.ReplaceAllString(r, "${1}${4}")
	}

	return r
}
