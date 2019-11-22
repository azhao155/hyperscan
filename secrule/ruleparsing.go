package secrule

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// RuleParser parses SecRule language files.
type RuleParser interface {
	Parse(input string, pf phraseLoaderCb, ilcb includeLoaderCb) (statements []Statement, err error)
}

var statementNameRegex = regexp.MustCompile(`(?s)^\w+([ \t]|\\\n)+`)
var targetRegex = regexp.MustCompile(`(?i)^!?&?(XML:/[^|\s,]+|\w+:/(\\.|[^/\\])+/|\w+:'(\\.|[^'\\])+'|\w+:[^|\s,]+|\w+)`)
var doubleQuotedStringRegex = regexp.MustCompile(`^"(\\.|\\\n|[^"\\])*"`)
var singleQuotedStringRegex = regexp.MustCompile(`^'(\\.|\\\n|[^'\\])*'`)
var nonQuotedStringRegex = regexp.MustCompile(`^[^ \t]+`)
var argSpaceRegex = regexp.MustCompile(`(?s)^([ \t]|\\\n)+`)
var operatorRegex = regexp.MustCompile(`^@\w+`)
var actionRegex = regexp.MustCompile(`^(\w+:('(\\.|[^'\\])+'|[^,]+))|\w+`)
var variableMacroRegex = regexp.MustCompile(`%{(?P<variable>[^}]+)}`)
var setVarParameterRegex = regexp.MustCompile(`!?(?P<variable>[^=]+)(?P<operator>=[+-]?)?(?P<value>.+)?`)
var ctlParameterRegex = regexp.MustCompile(`(?P<setting>[^=]+)=(?P<value>.+)`)

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
	"@le":                   Le,
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
func (r *ruleParserImpl) Parse(input string, pf phraseLoaderCb, ilcb includeLoaderCb) (statements []Statement, err error) {
	statements = []Statement{}
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
		statementName = strings.ToLower(statementName)

		switch statementName {
		case "secrule":
			err = r.parseSecRule(rest, &curRule, &statements, pf)
			if err != nil {
				err = fmt.Errorf("parse error in SecRule on line %d: %s", lineNumber, err)
				return
			}
		case "secaction":
			err = r.parseSecActionStmt(rest, &curRule, &statements)
			if err != nil {
				err = fmt.Errorf("parse error in SecAction on line %d: %s", lineNumber, err)
				return
			}
		case "secmarker":
			err = r.parseSecMarker(rest, &curRule, &statements)
			if err != nil {
				err = fmt.Errorf("parse error in SecMarker on line %d: %s", lineNumber, err)
				return
			}
		case "secdefaultaction":
			// No-op for now.
		case "seccollectiontimeout":
			// No-op for now.
		case "seccomponentsignature":
			// No-op for now.
		case "include":
			if ilcb == nil {
				err = fmt.Errorf("rules include statement, but no loader callback was given")
				return
			}

			includeFilePath := strings.Trim(rest, " \\\t\r\n")
			var rr []Statement
			rr, err = ilcb(includeFilePath)
			if err != nil {
				err = fmt.Errorf("error in file included from line number %v: %v", lineNumber, err)
				return
			}
			statements = append(statements, rr...)

		default:
			err = fmt.Errorf("unknown statement on line %d: %s", lineNumber, stmt)
			return
		}
	}

	return
}

// Parse a single rule.
func (r *ruleParserImpl) parseSecRule(s string, curRule **Rule, statements *[]Statement, pf phraseLoaderCb) (err error) {
	ru := &RuleItem{}

	ru.Predicate.Targets, ru.Predicate.ExceptTargets, s, err = r.parseTargets(s)
	if err != nil {
		return
	}

	_, s = r.findConsume(argSpaceRegex, s)

	ru.Predicate.Op, ru.Predicate.Val, ru.Predicate.Neg, s, err = r.parseOperator(s)
	if err != nil {
		return
	}

	switch ru.Predicate.Op {
	case Pm:
		ru.PmPhrases = strings.Split(ru.Predicate.Val, " ")
	case Pmf, PmFromFile:
		if pf == nil {
			err = fmt.Errorf("rules contained @pmf but no loader callback was given")
			return
		}

		ru.PmPhrases, err = pf(ru.Predicate.Val)
		if err != nil {
			return
		}
	}

	//TODO: Expand macros that are available during initialization
	ru.Predicate.valMacroMatches = variableMacroRegex.FindAllStringSubmatch(ru.Predicate.Val, -1)
	_, s = r.findConsume(argSpaceRegex, s)

	rawActions, s, err := r.parseRawActions(s)
	if err != nil {
		return
	}

	_, s = r.findConsume(argSpaceRegex, s)
	s, _ = r.nextArg(s)
	if s != "" {
		err = fmt.Errorf("unexpected arg: %s", s)
		return
	}

	var id int
	var hasChainAction bool
	var phase int
	ru.Actions,
		id,
		ru.Transformations,
		hasChainAction,
		phase,
		err = parseActions(rawActions)
	if err != nil {
		err = fmt.Errorf("error while parsing actions: %s", err)
		return
	}

	if (*curRule).ID == 0 {
		if id == 0 {
			err = fmt.Errorf("missing ID")
			return
		}

		(*curRule).ID = id
	}

	if phase != 0 {
		if (*curRule).Phase != 0 {
			err = fmt.Errorf("rule chain has conflicting phases")
			return
		}

		(*curRule).Phase = phase
	}

	(*curRule).Items = append((*curRule).Items, *ru)

	if !hasChainAction {
		// End of rule chain
		*statements = append(*statements, *curRule)
		*curRule = &Rule{}
	}

	return
}

// Parse a single SecAction statement.
func (r *ruleParserImpl) parseSecActionStmt(s string, curRule **Rule, statements *[]Statement) (err error) {
	actionStmt := &ActionStmt{}

	rawActions, s, err := r.parseRawActions(s)
	if err != nil {
		return
	}

	_, s = r.findConsume(argSpaceRegex, s)
	s, _ = r.nextArg(s)
	if s != "" {
		err = fmt.Errorf("unexpected arg: %s", s)
		return
	}

	actionStmt.Actions,
		actionStmt.ID,
		_,
		_,
		actionStmt.Phase,
		err = parseActions(rawActions)

	if actionStmt.ID == 0 {
		err = fmt.Errorf("missing ID")
		return
	}

	*statements = append(*statements, actionStmt)

	return
}

// Parse a single SecAction statement.
func (r *ruleParserImpl) parseSecMarker(s string, curRule **Rule, statements *[]Statement) (err error) {
	marker := &Marker{}

	marker.Label, s = r.nextArg(s)

	s, _ = r.nextArg(s)
	if s != "" {
		err = fmt.Errorf("unexpected arg: %s", s)
		return
	}

	*statements = append(*statements, marker)

	return
}

// Parse a SecRule targets field (aka. variables field).
func (r *ruleParserImpl) parseTargets(s string) (targets []Target, exceptTargets []Target, rest string, err error) {
	s, rest = r.nextArg(s)

	for {
		var targetStr string
		targetStr, s = r.findConsume(targetRegex, s)
		if targetStr == "" {
			err = fmt.Errorf("unable to parse targets")
			return
		}

		isNegate := false
		if targetStr[0] == '!' {
			isNegate = true
			targetStr = targetStr[1:]
		}

		isCount := false
		if targetStr[0] == '&' {
			isCount = true
			targetStr = targetStr[1:]
		}

		var name, selector string
		colonIdx := strings.Index(targetStr, ":")
		if colonIdx != -1 {
			name = targetStr[:colonIdx]
			selector = targetStr[colonIdx+1:]
		} else {
			name = targetStr
		}

		if len(selector) >= 2 && selector[0] == '\'' && selector[len(selector)-1] == '\'' {
			// Reusing nextArg to unquote and unescape
			selector, _ = r.nextArg(selector)
		}

		isRegexSelector := false
		if name != "XML" && len(selector) >= 2 && selector[0] == '/' && selector[len(selector)-1] == '/' {
			isRegexSelector = true
			selector = selector[1 : len(selector)-1]

			// Ensure early that the regexp selector is valid, so we can fail with a helpful error message otherwise.
			_, err = regexp.Compile(selector)
			if err != nil {
				err = fmt.Errorf("invalid regex target selector: %v", err)
				return
			}
		}

		target := Target{
			Name:            name,
			Selector:        selector,
			IsRegexSelector: isRegexSelector,
			IsCount:         isCount,
		}

		if isNegate {
			exceptTargets = append(exceptTargets, target)
		} else {
			targets = append(targets, target)
		}

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
			err = fmt.Errorf("unable to parse operator")
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
			err = fmt.Errorf("unable to parse actions")
			return
		}

		var k, v string
		k, v = r.parseActionKeyValue(a)
		k = strings.ToLower(k)
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

func parseActions(rawActions []RawAction) (
	actions []Action,
	id int,
	transformations []Transformation,
	hasChainAction bool,
	phase int,
	err error) {

	for _, a := range rawActions {
		switch a.Key {

		case "id":
			id, err = strconv.Atoi(a.Val)
			if err != nil {
				return
			}

		case "chain":
			hasChainAction = true

		case "allow":
			actions = append(actions, &AllowAction{})

		case "deny":
			actions = append(actions, &DenyAction{})

		case "msg":
			actions = append(actions, &MsgAction{Msg: parseValue(a.Val)})

		case "logdata":
			actions = append(actions, &LogDataAction{LogData: parseValue(a.Val)})

		case "t":
			if t, ok := transformationsMap[strings.ToLower(a.Val)]; ok {
				transformations = append(transformations, t)
			} else {
				err = fmt.Errorf("unknown transformation: %s", a.Val)
				return
			}

		case "setvar":
			var sv SetVarAction
			sv, err = parseSetVarAction(a.Val)
			if err != nil {
				return
			}

			actions = append(actions, &sv)

		case "nolog":
			actions = append(actions, &NoLogAction{})

		case "log":
			actions = append(actions, &LogAction{})

		case "phase":
			phase, err = parsePhase(a.Val)
			if err != nil {
				return
			}

		case "skipafter":
			actions = append(actions, &SkipAfterAction{Label: a.Val})

		case "capture":
			actions = append(actions, &CaptureAction{})

		case "ctl":
			var ctl CtlAction
			ctl, err = parseCtlAction(a.Val)
			if err != nil {
				return
			}

			actions = append(actions, &ctl)
		default:
			// TODO support all actions and do a proper error here for unknown actions
			var rawAction RawAction
			rawAction = a
			actions = append(actions, &rawAction)

		}
	}

	return
}

func parseSetVarAction(parameter string) (sv SetVarAction, err error) {
	matches := setVarParameterRegex.FindStringSubmatch(parameter)
	if matches == nil {
		err = fmt.Errorf("unsupported parameter %s for setvar operation", parameter)
		return
	}

	// TODO: potential optimization (replace map with variables)
	result := findStringSubmatchMap(setVarParameterRegex, parameter)
	if parameter[0] == '!' {
		result["operator"] = "!"
	}

	// Default values
	if result["operator"] == "" {
		result["operator"] = "="
	}

	if result["value"] == "" {
		result["value"] = "1"
	}

	op, err := toSetvarOperator(result["operator"])
	if err != nil {
		return
	}

	varMacroMatches := variableMacroRegex.FindAllStringSubmatch(result["variable"], -1)
	valMacroMatches := variableMacroRegex.FindAllStringSubmatch(result["value"], -1)

	sv = SetVarAction{
		variable:        result["variable"],
		operator:        op,
		value:           result["value"],
		varMacroMatches: varMacroMatches,
		valMacroMatches: valMacroMatches,
	}

	return
}

func parseCtlAction(parameter string) (ctl CtlAction, err error) {
	matches := ctlParameterRegex.FindStringSubmatch(parameter)
	if matches == nil {
		err = fmt.Errorf("unsupported parameter %s for ctl operation", parameter)
		return
	}

	result := findStringSubmatchMap(ctlParameterRegex, parameter)

	ctl = CtlAction{
		setting: result["setting"],
		value:   result["value"],
	}

	return
}

func findStringSubmatchMap(r *regexp.Regexp, str string) map[string]string {
	match := r.FindStringSubmatch(str)
	if match == nil {
		return nil
	}

	submatchMap := make(map[string]string)
	for i, name := range r.SubexpNames() {
		if i != 0 {
			submatchMap[name] = match[i]
		}
	}

	return submatchMap
}

func parsePhase(s string) (phase int, err error) {
	switch s {
	case "1":
		phase = 1
	case "2", "request":
		phase = 2
	case "3":
		phase = 3
	case "4", "response":
		phase = 4
	case "5", "logging":
		phase = 5
	default:
		err = fmt.Errorf("unknown phase: %s", s)
	}

	return
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

// A "value" is a string with macros, or sometimes just an integer value. It is used for logging and comparisons.
// Example: "Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}".
func parseValue(s string) (e Value) {
	// TODO remove (r *ruleParserImpl) from other funcs...

	// Append macro-tokens and possibly the string tokens tokens between them.
	var pos int
	for _, match := range variableMacroRegex.FindAllStringSubmatchIndex(s, -1) {
		if pos != match[0] {
			e = append(e, StringToken(s[pos:match[0]]))
		}

		macroName := s[match[0]+2 : match[1]-1] // Get rid of "%{" and "}"
		macroName = strings.ToLower(macroName)
		e = append(e, MacroToken(macroName))
		pos = match[1]
	}

	// If there were macros, append the remainder as a string literal.
	if len(e) > 0 {
		if pos != len(s) {
			e = append(e, StringToken(s[pos:len(s)]))
		}
		return
	}

	// There were no macros. Try if the value is just an int token.
	n, err := strconv.Atoi(s)
	if err == nil {
		e = append(e, IntToken(n))
		return
	}

	// The value is a string literal.
	e = append(e, StringToken(s))

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
