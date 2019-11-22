package secrule

import (
	"strings"
)

type environment struct {
	txVars         map[string]object // Case insensitive key map for ascii values only
	matchedVar     []byte
	matchedVarName []byte
	requestLine    []byte
	hostHeader     []byte

	// TODO support other collections besides TX
}

func newEnvironment(scanResults *ScanResults) environment {
	return environment{
		txVars:      make(map[string]object),
		requestLine: scanResults.requestLine,
		hostHeader:  scanResults.hostHeader,
	}
}

func (cim environment) get(k string) (v object, ok bool) {
	v, ok = cim.txVars[strings.ToLower(k)]
	return
}

func (cim environment) set(k string, v object) {
	cim.txVars[strings.ToLower(k)] = v
}

func (cim environment) delete(k string) {
	delete(cim.txVars, strings.ToLower(k))
}

func (cim environment) hasKey(k string) (ok bool) {
	_, ok = cim.txVars[strings.ToLower(k)]
	return
}
