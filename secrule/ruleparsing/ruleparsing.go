package ruleparsing

import (
	sr "azwaf/secrule"
	ast "azwaf/secrule/ast"

	"fmt"
	"regexp"
	"strconv"
	"strings"
)

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

var transformationsMap = map[string]ast.Transformation{
	"cmdline":            ast.CmdLine,
	"compresswhitespace": ast.CompressWhitespace,
	"cssdecode":          ast.CSSDecode,
	"hexencode":          ast.HexEncode,
	"htmlentitydecode":   ast.HTMLEntityDecode,
	"jsdecode":           ast.JsDecode,
	"length":             ast.Length,
	"lowercase":          ast.Lowercase,
	"none":               ast.None,
	"normalisepath":      ast.NormalisePath,
	"normalisepathwin":   ast.NormalisePathWin,
	"normalizepath":      ast.NormalizePath,
	"normalizepathwin":   ast.NormalizePathWin,
	"removecomments":     ast.RemoveComments,
	"removenulls":        ast.RemoveNulls,
	"removewhitespace":   ast.RemoveWhitespace,
	"replacecomments":    ast.ReplaceComments,
	"sha1":               ast.Sha1,
	"urldecode":          ast.URLDecode,
	"urldecodeuni":       ast.URLDecodeUni,
	"utf8tounicode":      ast.Utf8toUnicode,
}

var operatorsMap = map[string]ast.Operator{
	"@beginswith":           ast.BeginsWith,
	"@endswith":             ast.EndsWith,
	"@contains":             ast.Contains,
	"@containsword":         ast.ContainsWord,
	"@detectsqli":           ast.DetectSQLi,
	"@detectxss":            ast.DetectXSS,
	"@eq":                   ast.Eq,
	"@ge":                   ast.Ge,
	"@gt":                   ast.Gt,
	"@le":                   ast.Le,
	"@lt":                   ast.Lt,
	"@pm":                   ast.Pm,
	"@pmf":                  ast.Pmf,
	"@pmfromfile":           ast.PmFromFile,
	"@rx":                   ast.Rx,
	"@streq":                ast.Streq,
	"@strmatch":             ast.Strmatch,
	"@validatebyterange":    ast.ValidateByteRange,
	"@validateurlencoding":  ast.ValidateURLEncoding,
	"@validateutf8encoding": ast.ValidateUtf8Encoding,
	"@within":               ast.Within,
	"@geolookup":            ast.GeoLookup,
	"@ipmatch":              ast.IPMatch,
	"@ipmatchfromfile":      ast.IPMatchFromFile,
	"@rbl":                  ast.Rbl,
}

var ctlActionSettingsMap = map[string]ast.CtlActionSetting{
	"auditengine":              ast.AuditEngine,
	"auditlogparts":            ast.AuditLogParts,
	"forcerequestbodyvariable": ast.ForceRequestBodyVariable,
	"requestbodyaccess":        ast.RequestBodyAccess,
	"requestbodyprocessor":     ast.RequestBodyProcessor,
	"ruleengine":               ast.RuleEngine,
	"ruleremovebyid":           ast.RuleRemoveByID,
	"ruleremovebytag":          ast.RuleRemoveByTag,
	"ruleremovetargetbyid":     ast.RuleRemoveTargetByID,
	"ruleremovetargetbytag":    ast.RuleRemoveTargetByTag,
}

// TargetNamesFromStr gets TargetName enums from strings. Ensure this is in sync with TargetNamesStrings and the TargetName const iota block.
var TargetNamesFromStr = map[string]ast.TargetName{
	"ARGS":                         ast.TargetArgs,
	"ARGS_COMBINED_SIZE":           ast.TargetArgsCombinedSize,
	"ARGS_GET":                     ast.TargetArgsGet,
	"ARGS_GET_NAMES":               ast.TargetArgsGetNames,
	"ARGS_NAMES":                   ast.TargetArgsNames,
	"ARGS_POST":                    ast.TargetArgsPost,
	"DURATION":                     ast.TargetDuration,
	"FILES":                        ast.TargetFiles,
	"FILES_COMBINED_SIZE":          ast.TargetFilesCombinedSize,
	"FILES_NAMES":                  ast.TargetFilesNames,
	"GEO":                          ast.TargetGeo,
	"IP":                           ast.TargetIP,
	"MATCHED_VAR":                  ast.TargetMatchedVar,
	"MATCHED_VAR_NAME":             ast.TargetMatchedVarName,
	"MATCHED_VARS":                 ast.TargetMatchedVars,
	"MATCHED_VARS_NAMES":           ast.TargetMatchedVarsNames,
	"MULTIPART_STRICT_ERROR":       ast.TargetMultipartStrictError,
	"MULTIPART_UNMATCHED_BOUNDARY": ast.TargetMultipartUnmatchedBoundary,
	"QUERY_STRING":                 ast.TargetQueryString,
	"REMOTE_ADDR":                  ast.TargetRemoteAddr,
	"REQBODY_ERROR":                ast.TargetReqbodyError,
	"REQBODY_PROCESSOR":            ast.TargetReqbodyProcessor,
	"REQUEST_BASENAME":             ast.TargetRequestBasename,
	"REQUEST_BODY":                 ast.TargetRequestBody,
	"REQUEST_COOKIES":              ast.TargetRequestCookies,
	"REQUEST_COOKIES_NAMES":        ast.TargetRequestCookiesNames,
	"REQUEST_FILENAME":             ast.TargetRequestFilename,
	"REQUEST_HEADERS":              ast.TargetRequestHeaders,
	"REQUEST_HEADERS_NAMES":        ast.TargetRequestHeadersNames,
	"REQUEST_LINE":                 ast.TargetRequestLine,
	"REQUEST_METHOD":               ast.TargetRequestMethod,
	"REQUEST_PROTOCOL":             ast.TargetRequestProtocol,
	"REQUEST_URI":                  ast.TargetRequestURI,
	"REQUEST_URI_RAW":              ast.TargetRequestURIRaw,
	"RESOURCE":                     ast.TargetResource,
	"RESPONSE_BODY":                ast.TargetResponseBody,
	"RESPONSE_STATUS":              ast.TargetResponseStatus,
	"TX":                           ast.TargetTx,
	"UNIQUE_ID":                    ast.TargetUniqueID,
	"WEBSERVER_ERROR_LOG":          ast.TargetWebserverErrorLog,
	"XML":                          ast.TargetXML,
}

var envVarNamesFromStr = map[string]ast.EnvVarName{
	"ip":                               ast.EnvVarIP,
	"matched_var":                      ast.EnvVarMatchedVar,
	"matched_var_name":                 ast.EnvVarMatchedVarName,
	"multipart_boundary_quoted":        ast.EnvVarMultipartBoundaryQuoted,
	"multipart_boundary_whitespace":    ast.EnvVarMultipartBoundaryWhitespace,
	"multipart_data_after":             ast.EnvVarMultipartDataAfter,
	"multipart_data_before":            ast.EnvVarMultipartDataBefore,
	"multipart_file_limit_exceeded":    ast.EnvVarMultipartFileLimitExceeded,
	"multipart_header_folding":         ast.EnvVarMultipartHeaderFolding,
	"multipart_invalid_header_folding": ast.EnvVarMultipartInvalidHeaderFolding,
	"multipart_invalid_quoting":        ast.EnvVarMultipartInvalidQuoting,
	"multipart_lf_line":                ast.EnvVarMultipartLfLine,
	"multipart_semicolon_missing":      ast.EnvVarMultipartSemicolonMissing, // Note: same as multipart_missing_semicolon
	"multipart_missing_semicolon":      ast.EnvVarMultipartSemicolonMissing, // Note: same as multipart_semicolon_missing
	"remote_addr":                      ast.EnvVarRemoteAddr,
	"reqbody_error_msg":                ast.EnvVarReqbodyErrorMsg,
	"reqbody_processor":                ast.EnvVarReqbodyProcessor,
	"reqbody_processor_error":          ast.EnvVarReqbodyProcessorError,
	"request_headers":                  ast.EnvVarRequestHeaders,
	"request_line":                     ast.EnvVarRequestLine,
	"request_method":                   ast.EnvVarRequestMethod,
	"rule":                             ast.EnvVarRule,
	"tx":                               ast.EnvVarTx,
	"request_protocol":                 ast.EnvVarRequestProtocol,
}

type ruleParserImpl struct {
}

// NewRuleParser creates a secrule.RuleParser.
func NewRuleParser() sr.RuleParser {
	return &ruleParserImpl{}
}

// Parse a ruleset.
func (r *ruleParserImpl) Parse(input string, pf sr.PhraseLoaderCb, ilcb sr.IncludeLoaderCb) (statements []ast.Statement, err error) {
	statements = []ast.Statement{}
	curRule := &ast.Rule{}
	rest := input
	lineNumber := 0
	for {
		var stmt string
		stmt, rest = nextStatement(rest, &lineNumber)
		if stmt == "" {
			// There were no more statements
			break
		}

		// Sometimes only the first line in a multiline statement is commented out, leaving dangling args.
		if stmt[0] == '"' {
			continue
		}

		statementName, rest := findConsume(statementNameRegex, stmt)
		statementName = strings.Trim(statementName, " \\\t\r\n")
		statementName = strings.ToLower(statementName)

		switch statementName {
		case "secrule":
			err = parseSecRule(rest, &curRule, &statements, pf)
			if err != nil {
				err = fmt.Errorf("parse error in SecRule on line %d: %s", lineNumber, err)
				return
			}
		case "secaction":
			err = parseSecActionStmt(rest, &curRule, &statements)
			if err != nil {
				err = fmt.Errorf("parse error in SecAction on line %d: %s", lineNumber, err)
				return
			}
		case "secmarker":
			err = parseSecMarker(rest, &curRule, &statements)
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
			var rr []ast.Statement
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

	err = checkForUnsupportedFeatures(&statements)
	if err != nil {
		return
	}

	return
}

// Parse a single rule.
func parseSecRule(s string, curRule **ast.Rule, statements *[]ast.Statement, pf sr.PhraseLoaderCb) (err error) {
	ru := &ast.RuleItem{}

	ru.Predicate.Targets, ru.Predicate.ExceptTargets, s, err = parseTargets(s)
	if err != nil {
		return
	}

	_, s = findConsume(argSpaceRegex, s)

	ru.Predicate.Op, ru.Predicate.Val, ru.Predicate.Neg, s, err = parseOperator(s)
	if err != nil {
		return
	}

	switch ru.Predicate.Op {
	case ast.Pm:
		ru.PmPhrases = strings.Split(ru.Predicate.Val.String(), " ")
	case ast.Pmf, ast.PmFromFile:
		if pf == nil {
			err = fmt.Errorf("rules contained @pmf but no loader callback was given")
			return
		}

		ru.PmPhrases, err = pf(ru.Predicate.Val.String())
		if err != nil {
			return
		}
	}

	_, s = findConsume(argSpaceRegex, s)

	rawActions, s, err := parseRawActions(s)
	if err != nil {
		return
	}

	_, s = findConsume(argSpaceRegex, s)
	s, _ = nextArg(s)
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
		*curRule = &ast.Rule{}
	}

	return
}

// Parse a single SecAction statement.
func parseSecActionStmt(s string, curRule **ast.Rule, statements *[]ast.Statement) (err error) {
	actionStmt := &ast.ActionStmt{}

	rawActions, s, err := parseRawActions(s)
	if err != nil {
		return
	}

	_, s = findConsume(argSpaceRegex, s)
	s, _ = nextArg(s)
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
func parseSecMarker(s string, curRule **ast.Rule, statements *[]ast.Statement) (err error) {
	marker := &ast.Marker{}

	marker.Label, s = nextArg(s)

	s, _ = nextArg(s)
	if s != "" {
		err = fmt.Errorf("unexpected arg: %s", s)
		return
	}

	*statements = append(*statements, marker)

	return
}

// Parse a SecRule targets field (aka. variables field).
func parseTargets(s string) (targets []ast.Target, exceptTargets []ast.Target, rest string, err error) {
	s, rest = nextArg(s)

	for {
		var targetStr string
		targetStr, s = findConsume(targetRegex, s)
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

		var nameStr, selector string
		colonIdx := strings.Index(targetStr, ":")
		if colonIdx != -1 {
			nameStr = targetStr[:colonIdx]
			selector = targetStr[colonIdx+1:]
		} else {
			nameStr = targetStr
		}

		name, ok := TargetNamesFromStr[strings.ToUpper(nameStr)]
		if !ok {
			err = fmt.Errorf("invalid target name: %v", nameStr)
			return
		}

		if len(selector) >= 2 && selector[0] == '\'' && selector[len(selector)-1] == '\'' {
			// Reusing nextArg to unquote and unescape
			selector, _ = nextArg(selector)
		}

		isRegexSelector := false
		if name != ast.TargetXML && len(selector) >= 2 && selector[0] == '/' && selector[len(selector)-1] == '/' {
			isRegexSelector = true
			selector = selector[1 : len(selector)-1]

			// Ensure early that the regexp selector is valid, so we can fail with a helpful error message otherwise.
			_, err = regexp.Compile(selector)
			if err != nil {
				err = fmt.Errorf("invalid regex target selector: %v", err)
				return
			}
		} else {
			// Store non-regex selectors in lower case for easier case insensitive lookup.
			selector = strings.ToLower(selector)
		}

		target := ast.Target{
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

		_, s = findConsume(argSpaceRegex, s)
		if len(s) == 0 {
			return
		} else if s[0] == '|' || s[0] == ',' {
			// Another target will come
			s = s[1:]
			_, s = findConsume(argSpaceRegex, s)
		}
	}
}

// Parse a SecRule Operator field.
func parseOperator(s string) (op ast.Operator, val ast.Value, neg bool, rest string, err error) {
	op = ast.Rx

	s, rest = nextArg(s)

	if len(s) > 0 && s[0] == '!' {
		neg = true
		s = s[1:]
	}

	ops, s := findConsume(operatorRegex, s)
	if ops != "" {

		if o, ok := operatorsMap[strings.ToLower(ops)]; ok {
			op = o
		} else {
			err = fmt.Errorf("unable to parse operator")
			return
		}

		s = strings.TrimLeft(s, " ")
	}

	val, err = parseValue(s)
	if err != nil {
		return
	}

	// Special case for @validateByteRange
	if op == ast.ValidateByteRange {
		if val.HasMacros() {
			err = fmt.Errorf("macros in @validateByteRange not supported")
			return
		}

		val, err = parseValidateByteRangeVal(val.String())
		if err != nil {
			return
		}
	}

	return
}

// Parse a raw SecRule actions arg into RawAction key-value pairs.
func parseRawActions(s string) (actions []ast.RawAction, rest string, err error) {
	s, rest = nextArg(s)
	s = strings.Trim(s, " \t\r\n")

	// Empty action set is OK. For example last rule item in a rule chain might be like this.
	if s == "" {
		return
	}

	for {
		var a string
		a, s = findConsume(actionRegex, s)
		if a == "" {
			err = fmt.Errorf("unable to parse actions")
			return
		}

		var k, v string
		k, v = parseActionKeyValue(a)
		k = strings.ToLower(k)
		actions = append(actions, ast.RawAction{k, v})

		// Consume whitespace
		_, s = findConsume(argSpaceRegex, s)
		if len(s) == 0 {
			return
		} else if s[0] == ',' {
			// Another action will come
			s = s[1:]
			_, s = findConsume(argSpaceRegex, s)
		}
	}
}

func parseActions(rawActions []ast.RawAction) (
	actions []ast.Action,
	id int,
	transformations []ast.Transformation,
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
			actions = append(actions, &ast.AllowAction{})

		case "deny":
			actions = append(actions, &ast.DenyAction{})

		case "msg":
			var v ast.Value
			v, err = parseValue(a.Val)
			if err != nil {
				return
			}

			actions = append(actions, &ast.MsgAction{Msg: v})

		case "logdata":
			var v ast.Value
			v, err = parseValue(a.Val)
			if err != nil {
				return
			}

			actions = append(actions, &ast.LogDataAction{LogData: v})

		case "t":
			if t, ok := transformationsMap[strings.ToLower(a.Val)]; ok {
				transformations = append(transformations, t)
			} else {
				err = fmt.Errorf("unknown transformation: %s", a.Val)
				return
			}

		case "setvar":
			var sv ast.SetVarAction
			sv, err = parseSetVarAction(a.Val)
			if err != nil {
				return
			}

			actions = append(actions, &sv)

		case "nolog":
			actions = append(actions, &ast.NoLogAction{})

		case "log":
			actions = append(actions, &ast.LogAction{})

		case "phase":
			phase, err = parsePhase(a.Val)
			if err != nil {
				return
			}

		case "skipafter":
			actions = append(actions, &ast.SkipAfterAction{Label: a.Val})

		case "capture":
			actions = append(actions, &ast.CaptureAction{})

		case "ctl":
			var ctl ast.CtlAction
			ctl, err = parseCtlAction(a.Val)
			if err != nil {
				return
			}

			actions = append(actions, &ctl)
		default:
			// TODO support all actions and do a proper error here for unknown actions
			var rawAction ast.RawAction
			rawAction = a
			actions = append(actions, &rawAction)

		}
	}

	return
}

func parseSetVarAction(parameter string) (sv ast.SetVarAction, err error) {
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

	var variable ast.Value
	variable, err = parseValue(result["variable"])
	if err != nil {
		return
	}

	var value ast.Value
	value, err = parseValue(result["value"])
	if err != nil {
		return
	}

	sv = ast.SetVarAction{
		Variable: variable,
		Operator: op,
		Value:    value,
	}

	return
}

func parseCtlAction(parameter string) (ctl ast.CtlAction, err error) {
	matches := ctlParameterRegex.FindStringSubmatch(parameter)
	if matches == nil {
		err = fmt.Errorf("unsupported parameter %s for ctl operation", parameter)
		return
	}

	result := findStringSubmatchMap(ctlParameterRegex, parameter)

	setting, ok := ctlActionSettingsMap[strings.ToLower(result["setting"])]
	if !ok {
		err = fmt.Errorf("unsupported setting %s for ctl operation", result["setting"])
		return
	}

	var value ast.Value
	value, err = parseValue(result["value"])
	if err != nil {
		return
	}

	ctl = ast.CtlAction{
		Setting: setting,
		Value:   value,
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
func nextStatement(input string, lineNumber *int) (stmt string, rest string) {
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
func nextArg(s string) (arg string, rest string) {
	qs, qsRest := findConsume(doubleQuotedStringRegex, s)
	if qs != "" {
		rest = qsRest
		qs = qs[1 : len(qs)-1]
		qs = strings.Replace(qs, `\"`, `"`, -1)
		qs = strings.Replace(qs, "\\\n", ` `, -1)
		qs = strings.Replace(qs, `\\`, `\`, -1)
		arg = qs
		return
	}

	qs, qsRest = findConsume(singleQuotedStringRegex, s)
	if qs != "" {
		rest = qsRest
		qs = qs[1 : len(qs)-1]
		qs = strings.Replace(qs, `\'`, `'`, -1)
		qs = strings.Replace(qs, "\\\n", ` `, -1)
		qs = strings.Replace(qs, `\\`, `\`, -1)
		arg = qs
		return
	}

	arg, rest = findConsume(nonQuotedStringRegex, s)
	return
}

// Parse a SecRule action key-value pair.
func parseActionKeyValue(s string) (key string, val string) {
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
func parseValue(s string) (e ast.Value, err error) {
	// Append macro-tokens and possibly the string tokens tokens between them.
	var pos int
	for _, match := range variableMacroRegex.FindAllStringSubmatchIndex(s, -1) {
		// If there was a string in between previous macro and this macro, append it as a StringToken.
		if pos != match[0] {
			e = append(e, ast.StringToken(s[pos:match[0]]))
		}

		// Parse the macro token.
		m := s[match[0]+2 : match[1]-1] // Get rid of "%{" and "}"
		m = strings.ToLower(m)
		macroParts := strings.Split(m, ".")
		if len(macroParts) == 1 {
			t, ok := envVarNamesFromStr[m]
			if !ok {
				err = fmt.Errorf("unsupported macro %s", m)
				return
			}
			e = append(e, ast.MacroToken{Name: t})
		} else if len(macroParts) == 2 {
			// This macro has a selector, so it refers to a collection.

			t, ok := envVarNamesFromStr[macroParts[0]]
			if !ok {
				err = fmt.Errorf("unsupported macro %s", m)
				return
			}

			// These are the only collection macros we support.
			if !(t == ast.EnvVarRequestHeaders || t == ast.EnvVarTx || t == ast.EnvVarIP || t == ast.EnvVarRule) {
				err = fmt.Errorf("unsupported macro %s", m)
				return
			}

			// For the request_headers macro we only support the "host" entry.
			if t == ast.EnvVarRequestHeaders && macroParts[1] != "host" {
				err = fmt.Errorf("unsupported macro %s", m)
				return
			}

			e = append(e, ast.MacroToken{Name: t, Selector: macroParts[1]})
		} else {
			err = fmt.Errorf("unsupported macro %s", m)
			return
		}

		pos = match[1]
	}

	// If there were macros, append the remainder as a string literal.
	if len(e) > 0 {
		if pos != len(s) {
			e = append(e, ast.StringToken(s[pos:len(s)]))
		}
		return
	}

	// There were no macros. Try if the value is just an int token.
	n, erratoi := strconv.Atoi(s)
	if erratoi == nil {
		e = append(e, ast.IntToken(n))
		return
	}

	// The value is a string literal.
	e = append(e, ast.StringToken(s))

	return
}

// Special for @validateByteRange is that the val will be stored as a Value{ValidateByteRangeToken{...}}.
func parseValidateByteRangeVal(s string) (val ast.Value, err error) {
	parts := strings.Split(s, ",")
	var t ast.ValidateByteRangeToken
	for _, part := range parts {
		r := strings.Split(part, "-")
		n := len(r)

		if n != 1 && n != 2 {
			err = fmt.Errorf("invalid @validateByteRange format")
			return
		}

		var from int
		if n == 1 || n == 2 {
			from, err = strconv.Atoi(r[0])
			if err != nil || from < 0 {
				err = fmt.Errorf("failed to parse number in @validateByteRange: %v", err)
				return
			}
		}

		if n == 1 {
			t.AllowedBytes[from] = true
		} else if n == 2 {
			var to int
			to, err = strconv.Atoi(r[1])
			if err != nil || to > 255 {
				err = fmt.Errorf("failed to parse number in @validateByteRange: %v", err)
				return
			}

			if from >= to {
				err = fmt.Errorf("invalid range in @validateByteRange")
				return
			}

			for i := from; i <= to; i++ {
				t.AllowedBytes[i] = true
			}
		}
	}

	val = ast.Value{t}
	return
}

// Find the given regexp in str and return it. Return the remaining string after the match too.
func findConsume(re *regexp.Regexp, s string) (match string, rest string) {
	loc := re.FindStringIndex(s)
	if loc == nil {
		rest = s
		return
	}

	match = s[loc[0]:loc[1]]
	rest = s[loc[1]:]
	return
}

func toSetvarOperator(opStr string) (ast.SetVarActionOperator, error) {
	switch opStr {
	case "=":
		return ast.Set, nil
	case "=+":
		return ast.Increment, nil
	case "=-":
		return ast.Decrement, nil
	case "!":
		return ast.DeleteVar, nil
	}

	return -1, fmt.Errorf("Unsupported operator %s", opStr)
}

func checkForUnsupportedFeatures(statements *[]ast.Statement) error {
	// Ensure that there are no rules that have scan-phase variables on the left with macros on the right.
	// We do not support this, because expanded macros are not available at the point in time when we stream scan through requests.
	for _, s := range *statements {
		switch s := s.(type) {
		case *ast.Rule:
			for _, item := range s.Items {
				for _, t := range item.Predicate.Targets {
					if t.IsCount || item.Predicate.Op == ast.Ge || item.Predicate.Op == ast.Gt || item.Predicate.Op == ast.Le || item.Predicate.Op == ast.Lt {
						continue
					}
					switch t.Name {
					case ast.TargetArgs, ast.TargetArgsGet, ast.TargetArgsNames, ast.TargetFiles, ast.TargetFilesNames, ast.TargetQueryString, ast.TargetRequestBasename, ast.TargetRequestBody, ast.TargetRequestCookies, ast.TargetRequestCookiesNames, ast.TargetRequestFilename, ast.TargetRequestHeaders, ast.TargetRequestHeadersNames, ast.TargetRequestURI, ast.TargetRequestURIRaw, ast.TargetXML:
						if item.Predicate.Val.HasMacros() {
							return fmt.Errorf("rule %d is scanning for a macro in the scan-phase variable %s, which is unsupported by this SecRule engine", s.ID, ast.TargetNamesStrings[t.Name])
						}
						// There are a few scan-phase variables that are exempt from this restriction and have workarounds because they are used in CRS:
						//     "REQUEST_LINE", "REQUEST_METHOD", "REQUEST_PROTOCOL"
					}
				}
			}
		}
	}

	return nil
}
