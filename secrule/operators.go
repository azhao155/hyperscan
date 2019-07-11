package secrule

import (
	li "azwaf/libinjection"
	"strconv"
	"strings"
)

var operatorFuncsMap = map[Operator]operatorFunc{
	DetectSQLi:   detectSQLiOperatorEval,
	DetectXSS:    detectXSSOperatorEval,
	Eq:           equalOperatorEval,
	Ge:           greaterOrEqualOperatorEval,
	Gt:           greaterThanOperatorEval,
	Le:           lessOrEqualOperatorEval,
	Lt:           lessThanOperatorEval,
	BeginsWith:   beginsWithOperatorEval,
	EndsWith:     endsWithOperatorEval,
	Contains:     containsOperatorEval,
	ContainsWord: containsWordOperatorEval,
	Streq:        strEqOperatorEval,
	Strmatch:     containsOperatorEval,
	Within:       wordListSearchOperatorEval,
	Pm:           wordListSearchOperatorEval,
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

func beginsWithOperatorEval(target string, value string) (bool, string, error) {
	return strings.HasPrefix(target, value), "", nil
}

func endsWithOperatorEval(target string, value string) (bool, string, error) {
	return strings.HasSuffix(target, value), "", nil
}

func containsOperatorEval(target string, value string) (bool, string, error) {
	return strings.Contains(target, value), "", nil
}

func containsWordOperatorEval(target string, value string) (bool, string, error) {
	return strings.Contains(target, " "+value+" "), "", nil
}

func strEqOperatorEval(target string, value string) (bool, string, error) {
	return target == value, "", nil
}

func wordListSearchOperatorEval(target string, value string) (bool, string, error) {
	words := strings.Split(value, " ")
	for _, w := range words {
		if target == w {
			return true, "", nil
		}
	}
	return false, "", nil
}
