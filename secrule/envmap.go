package secrule

import (
	"strings"
)

// Case insensitive key map for ascii values only
// TODO: Convert to map of maps to support other collections besides TX.
type envMap struct {
	txVars         map[string]object
	matchedVar     []byte
	matchedVarName []byte
	requestLine    []byte
	hostHeader     []byte
}

func newEnvMap(scanResults *ScanResults) envMap {
	return envMap{
		txVars:      make(map[string]object),
		requestLine: scanResults.requestLine,
		hostHeader:  scanResults.hostHeader,
	}
}

func (cim envMap) get(k string) (v object, ok bool) {
	v, ok = cim.txVars[strings.ToLower(k)]
	return
}

func (cim envMap) set(k string, v object) {
	cim.txVars[strings.ToLower(k)] = v
}

func (cim envMap) delete(k string) {
	delete(cim.txVars, strings.ToLower(k))
}

func (cim envMap) hasKey(k string) (ok bool) {
	_, ok = cim.txVars[strings.ToLower(k)]
	return
}
