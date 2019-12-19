package ruleevaluation

import (
	ast "azwaf/secrule/ast"

	li "azwaf/libinjection"
	"bytes"
	"regexp"
)

var operatorFuncsMap = map[ast.Operator]operatorFunc{
	ast.DetectSQLi:   detectSQLiOperatorEval,
	ast.DetectXSS:    detectXSSOperatorEval,
	ast.Eq:           equalOperatorEval,
	ast.Ge:           greaterOrEqualOperatorEval,
	ast.Gt:           greaterThanOperatorEval,
	ast.Le:           lessOrEqualOperatorEval,
	ast.Lt:           lessThanOperatorEval,
	ast.BeginsWith:   beginsWithOperatorEval,
	ast.EndsWith:     endsWithOperatorEval,
	ast.Contains:     containsOperatorEval,
	ast.ContainsWord: containsWordOperatorEval,
	ast.Streq:        strEqOperatorEval,
	ast.Strmatch:     containsOperatorEval,
	ast.Within:       wordListSearchOperatorEval,
	ast.Pm:           wordListSearchOperatorEval,
	ast.Rx:           rxOperatorEval,
}

type operatorFunc func(ast.Value, ast.Value) (bool, string, error)

func toOperatorFunc(op ast.Operator) operatorFunc {
	return operatorFuncsMap[op]
}

func detectSQLiOperatorEval(target ast.Value, _ ast.Value) (bool, string, error) {
	// TODO let IsSQLi take byte array, for fewer conversions
	found, fingerprint := li.IsSQLi(target.String())
	return found, fingerprint, nil
}

func detectXSSOperatorEval(target ast.Value, _ ast.Value) (bool, string, error) {
	// TODO let IsXSS take byte array, for fewer conversions
	found := li.IsXSS(target.String())
	return found, "", nil
}

func equalOperatorEval(target ast.Value, value ast.Value) (bool, string, error) {
	return target.Equal(value), "", nil
}

func greaterOrEqualOperatorEval(target ast.Value, value ast.Value) (bool, string, error) {
	// TODO also support this operator for non-int values. I think ModSec 3 falls back to string lengths in that case. See CRS rule 920370.

	targetInt, ok := target.Int()
	if !ok {
		return false, "", nil
	}

	valueInt, ok := value.Int()
	if !ok {
		return false, "", nil
	}

	return targetInt >= valueInt, "", nil
}

func greaterThanOperatorEval(target ast.Value, value ast.Value) (bool, string, error) {
	// TODO also support this operator for non-int values. I think ModSec 3 falls back to string lengths in that case. See CRS rule 920370.

	targetInt, ok := target.Int()
	if !ok {
		return false, "", nil
	}

	valueInt, ok := value.Int()
	if !ok {
		return false, "", nil
	}

	return targetInt > valueInt, "", nil
}

func lessOrEqualOperatorEval(target ast.Value, value ast.Value) (bool, string, error) {
	// TODO also support this operator for non-int values. I think ModSec 3 falls back to string lengths in that case. See CRS rule 920370.

	targetInt, ok := target.Int()
	if !ok {
		return false, "", nil
	}

	valueInt, ok := value.Int()
	if !ok {
		return false, "", nil
	}

	return targetInt <= valueInt, "", nil
}

func lessThanOperatorEval(target ast.Value, value ast.Value) (bool, string, error) {
	// TODO also support this operator for non-int values. I think ModSec 3 falls back to string lengths in that case. See CRS rule 920370.

	targetInt, ok := target.Int()
	if !ok {
		return false, "", nil
	}

	valueInt, ok := value.Int()
	if !ok {
		return false, "", nil
	}

	return targetInt <= valueInt, "", nil
}

func beginsWithOperatorEval(target ast.Value, value ast.Value) (bool, string, error) {
	return bytes.HasPrefix(target.Bytes(), value.Bytes()), "", nil
}

func endsWithOperatorEval(target ast.Value, value ast.Value) (bool, string, error) {
	return bytes.HasSuffix(target.Bytes(), value.Bytes()), "", nil
}

func containsOperatorEval(target ast.Value, value ast.Value) (bool, string, error) {
	return bytes.Contains(target.Bytes(), value.Bytes()), "", nil
}

func containsWordOperatorEval(target ast.Value, value ast.Value) (bool, string, error) {
	bb := value.Bytes()
	buf := make([]byte, 0, len(bb)+2)
	buf = append(buf, ' ')
	buf = append(buf, bb...)
	buf = append(buf, ' ')
	return bytes.Contains(target.Bytes(), buf), "", nil
}

func strEqOperatorEval(target ast.Value, value ast.Value) (bool, string, error) {
	return target.Equal(value), "", nil
}

func wordListSearchOperatorEval(target ast.Value, value ast.Value) (bool, string, error) {
	targetBytes := bytes.ToLower(target.Bytes())

	// TODO consider optimizing. Consider Hyperscan or a custom DFA to scan all in O(n) time (the scan-phase version of this already uses Hyperscan).
	words := bytes.Split(value.Bytes(), []byte{' '})
	for _, w := range words {
		w = bytes.ToLower(w)
		if bytes.Contains(targetBytes, w) {
			return true, "", nil
		}
	}

	return false, "", nil
}

// Note that this operator-function is only used during late scanning, when scanning for or in a variable.
// Most regex rules are not based on a variable, and can therefore be scanned during request scanning.
func rxOperatorEval(actual ast.Value, expected ast.Value) (bool, string, error) {
	rx, err := regexp.Compile(expected.String())
	if err != nil {
		return false, "", err
	}

	captureGroups := rx.FindSubmatch(actual.Bytes())
	// TODO find a way to return the capture groups up so they can be put in TX.1, etc.
	if len(captureGroups) > 0 {
		return true, string(captureGroups[0]), nil
	}

	return false, "", nil
}
