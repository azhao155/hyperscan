package secrule

import (
	li "azwaf/libinjection"
	"strconv"
)

var operatorFuncsMap = map[Operator]operatorFunc{
	DetectSQLi: detectSQLiOperatorEval,
	DetectXSS:  detectXSSOperatorEval,
	Eq:         equalOperatorEval,
	Ge:         greaterOrEqualOperatorEval,
	Gt:         greaterThanOperatorEval,
	Le:         lessOrEqualOperatorEval,
	Lt:         lessThanOperatorEval,
}

type operatorFunc func(string, string) (bool, string, error)

func toOperatorFunc(op Operator) operatorFunc {
	return operatorFuncsMap[op]
}

func detectSQLiOperatorEval(target string, value string) (bool, string, error) {
	found, fingerprint := li.IsSQLi(target)
	return found, fingerprint, nil
}

func detectXSSOperatorEval(target string, value string) (bool, string, error) {
	found := li.IsXSS(target)
	return found, "", nil
}

// TODO: optimization: use numeric value
func equalOperatorEval(target string, value string) (bool, string, error) {
	return target == value, "", nil
}

func greaterOrEqualOperatorEval(target string, value string) (bool, string, error) {
	t, err := strconv.Atoi(target)
	if err != nil {
		return false, "", err
	}

	v, err := strconv.Atoi(value)
	if err != nil {
		return false, "", err
	}

	return t >= v, "", nil
}

func greaterThanOperatorEval(target string, value string) (bool, string, error) {
	t, err := strconv.Atoi(target)
	if err != nil {
		return false, "", err
	}

	v, err := strconv.Atoi(value)
	if err != nil {
		return false, "", err
	}

	return t > v, "", nil
}

func lessOrEqualOperatorEval(target string, value string) (bool, string, error) {
	t, err := strconv.Atoi(target)
	if err != nil {
		return false, "", err
	}

	v, err := strconv.Atoi(value)
	if err != nil {
		return false, "", err
	}

	return t <= v, "", nil
}

func lessThanOperatorEval(target string, value string) (bool, string, error) {
	t, err := strconv.Atoi(target)
	if err != nil {
		return false, "", err
	}

	v, err := strconv.Atoi(value)
	if err != nil {
		return false, "", err
	}

	return t < v, "", nil
}
