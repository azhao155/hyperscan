package secrule

import (
	li "azwaf/libinjection"
)

type detectSQLiOperator struct {
}

func (dso *detectSQLiOperator) eval(target string, value string) (bool, string, error) {
	found, fingerprint := li.IsSQLi(target)
	return found, fingerprint, nil
}
