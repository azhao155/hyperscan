package secrule

import "strconv"

type environment struct {
	txVars map[string]Value

	matchedVar      Value
	matchedVars     []Value
	matchedVarName  Value
	matchedVarNames []Value
	requestLine     Value
	requestMethod   Value
	requestProtocol Value
	hostHeader      Value

	// TODO support other collections besides TX
}

func newEnvironment() *environment {
	return &environment{
		txVars: make(map[string]Value),
	}
}

func (cim environment) get(k string) (v Value, ok bool) {
	// Try first to get built-in variable values.
	switch k {
	case "request_method":
		return cim.requestMethod, true
	case "matched_var":
		return cim.matchedVar, true
	case "matched_var_name":
		return cim.matchedVarName, true
	case "request_line":
		return cim.requestLine, true
	case "request_headers.host":
		return cim.hostHeader, true
	}

	// Try in the tx-vars map.
	v, ok = cim.txVars[k]
	return
}

func (cim environment) set(k string, v Value) {
	cim.txVars[k] = v
}

func (cim environment) delete(k string) {
	delete(cim.txVars, k)
}

func (cim environment) hasKey(k string) (ok bool) {
	_, ok = cim.txVars[k]
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
