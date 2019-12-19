package ruleevaluation

import (
	sr "azwaf/secrule"
	ast "azwaf/secrule/ast"

	"fmt"
	"regexp"
	"strconv"
)

type environment struct {
	txTargetRegexSelectorsCompiled map[string]*regexp.Regexp // CRS has a few rules that uses regex selectors on TX-targets such as "SecRule TX:/^HEADER_NAME_/ ...". This holds the precompiled regexes.

	// Single-valued variables.
	hostHeader       ast.Value
	matchedVar       ast.Value
	matchedVarName   ast.Value
	reqbodyProcessor ast.Value
	requestLine      ast.Value
	requestMethod    ast.Value
	requestProtocol  ast.Value

	// Collections that can only be retrieved item by item.
	txVars map[string]ast.Value

	// Collections that can be retrieved as collections.
	matchedVars     []ast.Value
	matchedVarNames []ast.Value

	// TODO support collections such as ip and session
}

// NewEnvironment creates a new instance of an Environment.
func NewEnvironment(txTargetRegexSelectorsCompiled map[string]*regexp.Regexp) sr.Environment {
	return &environment{
		txTargetRegexSelectorsCompiled: txTargetRegexSelectorsCompiled,
		txVars:                         make(map[string]ast.Value),
	}
}

func (e *environment) Get(name ast.EnvVarName, selector string) (v ast.Value) {
	switch name {
	case ast.EnvVarRequestHeaders:
		if selector == "host" {
			return e.hostHeader
		}
	case ast.EnvVarMatchedVar:
		return e.matchedVar
	case ast.EnvVarMatchedVarName:
		return e.matchedVarName
	case ast.EnvVarReqbodyProcessor:
		return e.reqbodyProcessor
	case ast.EnvVarRequestLine:
		return e.requestLine
	case ast.EnvVarRequestMethod:
		return e.requestMethod
	case ast.EnvVarRequestProtocol:
		return e.requestProtocol
	case ast.EnvVarTx:
		v = e.txVars[selector]
	}

	return
}

// CRS has a few rules that uses regex selectors on TX-targets such as "SecRule TX:/^HEADER_NAME_/ ...".
// This func returns all TX-variables whose key matches a given selector.
func (e *environment) GetTxVarsViaRegexSelector(selector string) (vv []ast.Value) {
	for k, v := range e.txVars {
		rx := e.txTargetRegexSelectorsCompiled[selector]
		if rx == nil {
			panic(fmt.Sprintf("regex for TX-variable selector %s was not found in the precompiled set", selector))
		}

		if rx.MatchString(k) {
			vv = append(vv, v)
		}
	}

	return
}

func (e *environment) Set(name ast.EnvVarName, collectionKey string, val ast.Value) {
	switch name {
	case ast.EnvVarRequestHeaders:
		if collectionKey == "host" {
			e.hostHeader = val
		}
	case ast.EnvVarMatchedVar:
		e.matchedVar = val
	case ast.EnvVarMatchedVarName:
		e.matchedVarName = val
	case ast.EnvVarReqbodyProcessor:
		e.reqbodyProcessor = val
	case ast.EnvVarRequestLine:
		e.requestLine = val
	case ast.EnvVarRequestMethod:
		e.requestMethod = val
	case ast.EnvVarRequestProtocol:
		e.requestProtocol = val
	case ast.EnvVarTx:
		e.txVars[collectionKey] = val
	}
}

func (e *environment) Delete(name ast.EnvVarName, selector string) {
	switch name {
	case ast.EnvVarRequestHeaders:
		if selector == "host" {
			e.hostHeader = nil
		}
	case ast.EnvVarMatchedVar:
		e.matchedVar = nil
	case ast.EnvVarMatchedVarName:
		e.matchedVarName = nil
	case ast.EnvVarReqbodyProcessor:
		e.reqbodyProcessor = nil
	case ast.EnvVarRequestLine:
		e.requestLine = nil
	case ast.EnvVarRequestMethod:
		e.requestMethod = nil
	case ast.EnvVarRequestProtocol:
		e.requestProtocol = nil
	case ast.EnvVarTx:
		delete(e.txVars, selector)
	}
}

func (e *environment) GetCollection(name ast.EnvVarName) (vv []ast.Value) {
	switch name {
	case ast.EnvVarMatchedVars:
		return e.matchedVars
	case ast.EnvVarMatchedVarNames:
		return e.matchedVarNames
	}

	return
}

func (e *environment) ResetMatchesCollections() {
	e.matchedVars = []ast.Value{}
	e.matchedVarNames = []ast.Value{}
}

func (e *environment) UpdateMatches(matches []sr.Match) {
	for i, m := range matches {
		v := ast.Value{ast.StringToken(m.EntireFieldContent)}
		if n, err := strconv.Atoi(string(m.EntireFieldContent)); err == nil {
			v = ast.Value{ast.IntToken(n)}
		}

		e.matchedVars = append(e.matchedVars, v)

		// Prepend the target name, so it becomes for example "ARGS:myarg1".
		newLen := len(ast.TargetNamesStrings[m.TargetName]) + 1 + len(m.FieldName)
		fullVarName := make([]byte, 0, newLen)
		fullVarName = append(fullVarName, ast.TargetNamesStrings[m.TargetName]...)
		fullVarName = append(fullVarName, ':')
		fullVarName = append(fullVarName, m.FieldName...)
		vn := ast.Value{ast.StringToken(fullVarName)}
		e.matchedVarNames = append(e.matchedVarNames, vn)

		if i == (len(matches))-1 {
			e.matchedVar = v
			e.matchedVarName = vn
		}
	}
}

func (e *environment) ExpandMacros(v ast.Value) (output ast.Value) {
	output = make(ast.Value, 0, len(v)) // Output will contain at max the same number of tokens as input.

	for _, token := range v {
		// Replace with value from env if macro-token.
		if mt, ok := token.(ast.MacroToken); ok {

			v := e.Get(mt.Name, mt.Selector)
			if v != nil {
				output = append(output, v...)
			} else {
				// Macros that could not be resolved will result in blanks.
			}

			continue

		}

		// This was not a macro token, so just keep it as is.
		output = append(output, token)
	}

	return
}

// GetTxTargetRegexSelectorsCompiled finds RX-targets with regex selectors and precompiles them. CRS has a few of these, such as "SecRule TX:/^HEADER_NAME_/ ...".
func GetTxTargetRegexSelectorsCompiled(statements []ast.Statement) (rxs map[string]*regexp.Regexp, err error) {
	rxs = make(map[string]*regexp.Regexp)

	for _, statement := range statements {
		switch statement := statement.(type) {
		case *ast.Rule:
			for _, ruleItem := range statement.Items {
				for _, target := range ruleItem.Predicate.Targets {
					if target.Name == ast.TargetTx && target.IsRegexSelector {
						// Regex selectors are not case sensitive.
						rx := fmt.Sprintf("(?i:%s)", target.Selector)

						rxs[target.Selector], err = regexp.Compile(rx)
						if err != nil {
							err = fmt.Errorf("invalid TX-target regex selector %v: %v", target.Selector, err)
							return
						}
					}
				}
			}
		}
	}

	return
}
