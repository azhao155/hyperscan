package secrule

import (
	li "azwaf/libinjection"
)

type detectXSSOperator struct {
}

func (dso *detectXSSOperator) eval(target string, value string) (bool, string, error) {
	found := li.IsXSS(target)
	return found, "", nil
}
