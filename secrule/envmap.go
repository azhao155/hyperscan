package secrule

import "strings"

// Case insensitive key map for ascii values only
type envMap struct {
	m map[string]object
}

func newEnvMap() envMap {
	return envMap{m: make(map[string]object)}
}

func (cim envMap) get(k string) (v object, ok bool) {
	v, ok = cim.m[strings.ToLower(k)]
	return
}

func (cim envMap) set(k string, v object) {
	cim.m[strings.ToLower(k)] = v
}

func (cim envMap) delete(k string) {
	delete(cim.m, strings.ToLower(k))
}
