package secrule

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// RuleParser parses SecRule language files.
type RuleParser interface {
	Parse(input string) (rules []Rule, err error)
}

var statementNameRegex = regexp.MustCompile(`(?s)^\w+([ \t]|\\\n)+`)
var targetRegex = regexp.MustCompile(`(?i)^!?&?(XML:/[^|\s,]+|\w+:/(\\.|[^/\\])+/|\w+:'(\\.|[^'\\])+'|\w+:[^|\s,]+|\w+)`)
var doubleQuotedStringRegex = regexp.MustCompile(`^"(\\.|\\\n|[^"\\])*"`)
var singleQuotedStringRegex = regexp.MustCompile(`^'(\\.|\\\n|[^'\\])*'`)
var nonQuotedStringRegex = regexp.MustCompile(`^[^ \t]+`)
var argSpaceRegex = regexp.MustCompile(`(?s)^([ \t]|\\\n)+`)
var operatorRegex = regexp.MustCompile(`^@\w+`)
var actionRegex = regexp.MustCompile(`^(\w+:('(\\.|[^'\\])+'|[^,]+))|\w+`)

var transformationsMap = map[string]Transformation{
	"cmdline":            CmdLine,
	"compresswhitespace": CompressWhitespace,
	"cssdecode":          CSSDecode,
	"hexencode":          HexEncode,
	"htmlentitydecode":   HTMLEntityDecode,
	"jsdecode":           JsDecode,
	"length":             Length,
	"lowercase":          Lowercase,
	"none":               None,
	"normalisepath":      NormalisePath,
	"normalisepathwin":   NormalisePathWin,
	"normalizepath":      NormalizePath,
	"normalizepathwin":   NormalizePathWin,
	"removecomments":     RemoveComments,
	"removenulls":        RemoveNulls,
	"removewhitespace":   RemoveWhitespace,
	"replacecomments":    ReplaceComments,
	"sha1":               Sha1,
	"urldecode":          URLDecode,
	"urldecodeuni":       URLDecodeUni,
	"utf8tounicode":      Utf8toUnicode,
}

var operatorsMap = map[string]Operator{
	"@beginswith":           BeginsWith,
	"@endswith":             EndsWith,
	"@contains":             Contains,
	"@containsword":         ContainsWord,
	"@detectsqli":           DetectSQLi,
	"@detectxss":            DetectXSS,
	"@eq":                   Eq,
	"@ge":                   Ge,
	"@gt":                   Gt,
	"@lt":                   Lt,
	"@pm":                   Pm,
	"@pmf":                  Pmf,
	"@pmfromfile":           PmFromFile,
	"@rx":                   Rx,
	"@streq":                Streq,
	"@strmatch":             Strmatch,
	"@validatebyterange":    ValidateByteRange,
	"@validateurlencoding":  ValidateURLEncoding,
	"@validateutf8encoding": ValidateUtf8Encoding,
	"@within":               Within,
	"@geolookup":            GeoLookup,
	"@ipmatch":              IPMatch,
	"@ipmatchfromfile":      IPMatchFromFile,
	"@rbl":                  Rbl,
}

type ruleParserImpl struct {
}

// NewRuleParser creates a secrule.RuleParser.
func NewRuleParser() RuleParser {
	return &ruleParserImpl{}
}

// Parse a ruleset.
func (r *ruleParserImpl) Parse(input string) (rules []Rule, err error) {
	rules = []Rule{}
	curRule := &Rule{}
	rest := input
	lineNumber := 0
	for {
		var stmt string
		stmt, rest = r.nextStatement(rest, &lineNumber)
		if stmt == "" {
			// There were no more statements
			break
		}

		// Sometimes only the first line in a multiline statement is commented out, leaving dangling args.
		if stmt[0] == '"' {
			continue
		}

		statementName, rest := r.findConsume(statementNameRegex, stmt)
		statementName = strings.Trim(statementName, " \\\t\r\n")

		switch statementName {
		case "SecRule":
			err = r.parseSecRule(rest, &curRule, &rules)
			if err != nil {
				err = fmt.Errorf("Parse error in SecRule on line %d: %s", lineNumber, err)
				return
			}
		case "SecAction":
			// No-op for now.
		case "SecMarker":
			// No-op for now.
		case "SecDefaultAction":
			// No-op for now.
		case "SecCollectionTimeout":
			// No-op for now.
		case "SecComponentSignature":
			// No-op for now.
		default:
			err = fmt.Errorf("Unknown statement on line %d: %s", lineNumber, stmt)
			return
		}
	}

	return
}

// Parse a single rule.
func (r *ruleParserImpl) parseSecRule(s string, curRule **Rule, rules *[]Rule) (err error) {
	ru := &RuleItem{}

	ru.Targets, s, err = r.parseTargets(s)
	if err != nil {
		return
	}

	_, s = r.findConsume(argSpaceRegex, s)

	ru.Op, ru.Val, ru.Neg, s, err = r.parseOperator(s)
	if err != nil {
		return
	}

	_, s = r.findConsume(argSpaceRegex, s)

	ru.RawActions, s, err = r.parseRawActions(s)
	if err != nil {
		return
	}

	_, s = r.findConsume(argSpaceRegex, s)
	s, _ = r.nextArg(s)
	if s != "" {
		err = fmt.Errorf("Unexpected arg: %s", s)
		return
	}

	var id int
	var hasChainAction bool
	for _, a := range ru.RawActions {
		switch a.Key {
		case "id":
			id, err = strconv.Atoi(a.Val)
			if err != nil {
				return
			}
		case "chain":
			hasChainAction = true
		case "msg":
			ru.Msg = a.Val
		case "t":
			if t, ok := transformationsMap[strings.ToLower(a.Val)]; ok {
				ru.Transformations = append(ru.Transformations, t)
			} else {
				err = fmt.Errorf("Unknown transformation: %s", a.Val)
				return
			}
		case "setvar":
			ru.Actions = append(ru.Actions, newSetvarAction(a.Val))
		}
	}

	if (*curRule).ID == 0 {
		if id == 0 {
			err = fmt.Errorf("Missing ID")
			return
		}

		(*curRule).ID = id
	}

	(*curRule).Items = append((*curRule).Items, *ru)

	if !hasChainAction {
		// End of rule chain
		*rules = append(*rules, **curRule)
		*curRule = &Rule{}
	}

	return
}

// Parse a SecRule targets field (aka. variables field).
func (r *ruleParserImpl) parseTargets(s string) (targets []string, rest string, err error) {
	s, rest = r.nextArg(s)

	for {
		var target string
		target, s = r.findConsume(targetRegex, s)
		if target == "" {
			err = fmt.Errorf("Unable to parse targets")
			return
		}

		targets = append(targets, target)

		_, s = r.findConsume(argSpaceRegex, s)
		if len(s) == 0 {
			return
		} else if s[0] == '|' || s[0] == ',' {
			// Another target will come
			s = s[1:]
			_, s = r.findConsume(argSpaceRegex, s)
		}
	}
}

// Parse a SecRule Operator field.
func (r *ruleParserImpl) parseOperator(s string) (op Operator, val string, neg bool, rest string, err error) {
	op = Rx

	s, rest = r.nextArg(s)

	if len(s) > 0 && s[0] == '!' {
		neg = true
		s = s[1:]
	}

	ops, s := r.findConsume(operatorRegex, s)
	if ops != "" {

		if o, ok := operatorsMap[strings.ToLower(ops)]; ok {
			op = o
		} else {
			err = fmt.Errorf("Unable to parse operator")
			return
		}

		s = strings.TrimLeft(s, " ")
	}

	val = s

	return
}

// Parse a raw SecRule actions arg into RawAction key-value pairs.
func (r *ruleParserImpl) parseRawActions(s string) (actions []RawAction, rest string, err error) {
	s, rest = r.nextArg(s)
	s = strings.Trim(s, " \t\r\n")

	// Empty action set is OK. For example last rule item in a rule chain might be like this.
	if s == "" {
		return
	}

	for {
		var a string
		a, s = r.findConsume(actionRegex, s)
		if a == "" {
			err = fmt.Errorf("Unable to parse actions")
			return
		}

		var k, v string
		k, v = r.parseActionKeyValue(a)
		actions = append(actions, RawAction{k, v})

		// Consume whitespace
		_, s = r.findConsume(argSpaceRegex, s)
		if len(s) == 0 {
			return
		} else if s[0] == ',' {
			// Another action will come
			s = s[1:]
			_, s = r.findConsume(argSpaceRegex, s)
		}
	}
}

// Get the next full statement from the reader. Statements can continue on multiple lines using \.
func (r *ruleParserImpl) nextStatement(input string, lineNumber *int) (stmt string, rest string) {
	var sb strings.Builder
	rest = input
	for {
		var line string
		pos := strings.Index(rest, "\n")
		if pos == -1 {
			line = rest
			rest = ""
		} else {
			line = rest[:pos+1]
			rest = rest[pos+1:]
		}

		*lineNumber++

		lt := strings.Trim(line, " \t\r\n")

		if lt == "" && rest != "" {
			continue
		}

		if strings.HasPrefix(lt, "#") {
			continue
		}

		sb.WriteString(lt)

		if strings.HasSuffix(lt, "\\") {
			sb.WriteString("\n")
		} else {
			break
		}
	}

	stmt = sb.String()
	return
}

// Extract and unescape a single or double quoted string, or a non-quoted string without whitespaces, from the beginning of the given string, and return the rest.
func (r *ruleParserImpl) nextArg(s string) (arg string, rest string) {
	qs, qsRest := r.findConsume(doubleQuotedStringRegex, s)
	if qs != "" {
		rest = qsRest
		qs = qs[1 : len(qs)-1]
		qs = strings.Replace(qs, `\"`, `"`, -1)
		qs = strings.Replace(qs, "\\\n", ` `, -1)
		qs = strings.Replace(qs, `\\`, `\`, -1)
		arg = qs
		return
	}

	qs, qsRest = r.findConsume(singleQuotedStringRegex, s)
	if qs != "" {
		rest = qsRest
		qs = qs[1 : len(qs)-1]
		qs = strings.Replace(qs, `\'`, `'`, -1)
		qs = strings.Replace(qs, "\\\n", ` `, -1)
		qs = strings.Replace(qs, `\\`, `\`, -1)
		arg = qs
		return
	}

	arg, rest = r.findConsume(nonQuotedStringRegex, s)
	return
}

// Parse a SecRule action key-value pair.
func (r *ruleParserImpl) parseActionKeyValue(s string) (key string, val string) {
	pos := strings.Index(s, ":")
	if pos == -1 {
		key = s
		return
	}

	key = s[:pos]

	valStart := pos + 1
	valEnd := len(s) - 1
	if s[valStart] == '\'' {
		valStart++
		valEnd--
	}
	val = s[valStart : valEnd+1]

	return
}

// Find the given regexp in str and return it. Return the remaining string after the match too.
func (r *ruleParserImpl) findConsume(re *regexp.Regexp, s string) (match string, rest string) {
	loc := re.FindStringIndex(s)
	if loc == nil {
		rest = s
		return
	}

	match = s[loc[0]:loc[1]]
	rest = s[loc[1]:]
	return
}
