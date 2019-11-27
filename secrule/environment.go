package secrule

import "strconv"

type environment struct {
	txVars map[string]Value

	matchedVar      []byte
	matchedVarName  []byte
	requestLine     []byte
	requestMethod   []byte
	requestProtocol []byte
	hostHeader      []byte

	// TODO support other collections besides TX
}

func newEnvironment(scanResults *ScanResults) environment {
	return environment{
		txVars:          make(map[string]Value),
		requestLine:     scanResults.requestLine,
		requestMethod:   scanResults.requestMethod,
		requestProtocol: scanResults.requestProtocol,
		hostHeader:      scanResults.hostHeader,
	}
}

func (cim environment) get(k string) (v Value, ok bool) {
	// Try first to get built-in variable values.
	var p *[]byte
	switch k {
	case "request_method":
		p = &cim.requestMethod
	case "matched_var":
		p = &cim.matchedVar
	case "matched_var_name":
		p = &cim.matchedVarName
	case "request_line":
		p = &cim.requestLine
	case "request_headers.host":
		p = &cim.hostHeader
	}
	if p != nil {
		if n, err := strconv.Atoi(string(*p)); err == nil {
			return Value{IntToken(n)}, true
		}
		return Value{StringToken(*p)}, true
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
