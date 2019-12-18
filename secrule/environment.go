package secrule

import (
	"fmt"
	"regexp"
	"strconv"
)

type environment struct {
	txTargetRegexSelectorsCompiled map[string]*regexp.Regexp // CRS has a few rules that uses regex selectors on TX-targets such as "SecRule TX:/^HEADER_NAME_/ ...". This holds the precompiled regexes.

	// Single-valued variables.
	hostHeader       Value
	matchedVar       Value
	matchedVarName   Value
	reqbodyProcessor Value
	requestLine      Value
	requestMethod    Value
	requestProtocol  Value

	// Collections that can only be retrieved item by item.
	txVars map[string]Value

	// Collections that can be retrieved as collections.
	matchedVars     []Value
	matchedVarNames []Value

	// TODO support collections such as ip and session
}

func newEnvironment(txTargetRegexSelectorsCompiled map[string]*regexp.Regexp) *environment {
	return &environment{
		txTargetRegexSelectorsCompiled: txTargetRegexSelectorsCompiled,
		txVars:                         make(map[string]Value),
	}
}

func (cim *environment) get(name EnvVarName, selector string) (v Value) {
	switch name {
	case EnvVarRequestHeaders:
		if selector == "host" {
			return cim.hostHeader
		}
	case EnvVarMatchedVar:
		return cim.matchedVar
	case EnvVarMatchedVarName:
		return cim.matchedVarName
	case EnvVarReqbodyProcessor:
		return cim.reqbodyProcessor
	case EnvVarRequestLine:
		return cim.requestLine
	case EnvVarRequestMethod:
		return cim.requestMethod
	case EnvVarRequestProtocol:
		return cim.requestProtocol
	case EnvVarTx:
		v = cim.txVars[selector]
	}

	return
}

// CRS has a few rules that uses regex selectors on TX-targets such as "SecRule TX:/^HEADER_NAME_/ ...".
// This func returns all TX-variables whose key matches a given selector.
func (cim *environment) getTxVarsViaRegexSelector(selector string) (vv []Value) {
	for k, v := range cim.txVars {
		rx := cim.txTargetRegexSelectorsCompiled[selector]
		if rx == nil {
			panic(fmt.Sprintf("regex for TX-variable selector %s was not found in the precompiled set", selector))
		}

		if rx.MatchString(k) {
			vv = append(vv, v)
		}
	}

	return
}

func (cim *environment) set(name EnvVarName, collectionKey string, val Value) {
	switch name {
	case EnvVarRequestHeaders:
		if collectionKey == "host" {
			cim.hostHeader = val
		}
	case EnvVarMatchedVar:
		cim.matchedVar = val
	case EnvVarMatchedVarName:
		cim.matchedVarName = val
	case EnvVarReqbodyProcessor:
		cim.reqbodyProcessor = val
	case EnvVarRequestLine:
		cim.requestLine = val
	case EnvVarRequestMethod:
		cim.requestMethod = val
	case EnvVarRequestProtocol:
		cim.requestProtocol = val
	case EnvVarTx:
		cim.txVars[collectionKey] = val
	}
}

func (cim *environment) delete(name EnvVarName, selector string) {
	switch name {
	case EnvVarRequestHeaders:
		if selector == "host" {
			cim.hostHeader = nil
		}
	case EnvVarMatchedVar:
		cim.matchedVar = nil
	case EnvVarMatchedVarName:
		cim.matchedVarName = nil
	case EnvVarReqbodyProcessor:
		cim.reqbodyProcessor = nil
	case EnvVarRequestLine:
		cim.requestLine = nil
	case EnvVarRequestMethod:
		cim.requestMethod = nil
	case EnvVarRequestProtocol:
		cim.requestProtocol = nil
	case EnvVarTx:
		delete(cim.txVars, selector)
	}
}

func (cim *environment) getCollection(name EnvVarName) (vv []Value) {
	switch name {
	case EnvVarMatchedVars:
		return cim.matchedVars
	case EnvVarMatchedVarNames:
		return cim.matchedVarNames
	}

	return
}

func (cim *environment) resetMatchesCollections() {
	cim.matchedVars = []Value{}
	cim.matchedVarNames = []Value{}
}

func (cim *environment) updateMatches(matches []Match) {
	for i, m := range matches {
		v := Value{StringToken(m.EntireFieldContent)}
		if n, err := strconv.Atoi(string(m.EntireFieldContent)); err == nil {
			v = Value{IntToken(n)}
		}

		cim.matchedVars = append(cim.matchedVars, v)

		// Prepend the target name, so it becomes for example "ARGS:myarg1".
		newLen := len(TargetNamesStrings[m.TargetName]) + 1 + len(m.FieldName)
		fullVarName := make([]byte, 0, newLen)
		fullVarName = append(fullVarName, TargetNamesStrings[m.TargetName]...)
		fullVarName = append(fullVarName, ':')
		fullVarName = append(fullVarName, m.FieldName...)
		vn := Value{StringToken(fullVarName)}
		cim.matchedVarNames = append(cim.matchedVarNames, vn)

		if i == (len(matches))-1 {
			cim.matchedVar = v
			cim.matchedVarName = vn
		}
	}
}

// CRS has a few rules that uses regex selectors on TX-targets such as "SecRule TX:/^HEADER_NAME_/ ...". This func precompiles these.
func getTxTargetRegexSelectorsCompiled(statements []Statement) (rxs map[string]*regexp.Regexp, err error) {
	rxs = make(map[string]*regexp.Regexp)

	for _, statement := range statements {
		switch statement := statement.(type) {
		case *Rule:
			for _, ruleItem := range statement.Items {
				for _, target := range ruleItem.Predicate.Targets {
					if target.Name == TargetTx && target.IsRegexSelector {
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
