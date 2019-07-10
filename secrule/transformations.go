package secrule

import (
	"html"
	"net/url"
	"strings"
)

var whitespaceReplacer = strings.NewReplacer(" ", "", "\t", "", "\n", "", "\v", "", "\f", "", "\r", "")

func applyTransformations(s string, tt []Transformation) string {
	// TODO implement a trie for caching already done transformations

	orig := s
	for _, t := range tt {
		// TODO implement all transformations
		switch t {
		case CmdLine:
		case CompressWhitespace:
		case CSSDecode:
		case HexEncode:
		case HTMLEntityDecode:
			if strings.Contains(s, "&") {
				s = html.UnescapeString(s)
				// TODO ensure this aligns with the intended htmlEntityDecode functionality of SecRule-lang: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#htmlEntityDecode
				// TODO read https://golang.org/pkg/html/#UnescapeString closely. We need to think about if the unicode behaviour here is correct for SecRule-lang.
			}
		case JsDecode:
		case Length:
			// TODO is this really used? Isn't @ for this? Should we use the type-system to keep this as int here?
			s = string(len(s))
		case Lowercase:
			s = strings.ToLower(s)
		case None:
			s = orig
		case NormalisePath:
		case NormalisePathWin:
		case NormalizePath:
		case NormalizePathWin:
		case RemoveComments:
		case RemoveNulls:
		case RemoveWhitespace:
			if strings.ContainsAny(s, " \t\n\v\f\r") {
				s = whitespaceReplacer.Replace(s)
			}
		case ReplaceComments:
		case Sha1:
		case URLDecode, URLDecodeUni:
			tmp, err := url.PathUnescape(s)
			if err != nil {
				// TODO handle transformation error
				continue
			}
			s = tmp
		case Utf8toUnicode:
		}
	}

	return s
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
