package secrule

import (
	li "azwaf/libinjection"
	"bytes"
	"regexp"
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
	Rx:           rxOperatorEval,
}

type operatorFunc func(Value, Value) (bool, string, error)

func toOperatorFunc(op Operator) operatorFunc {
	return operatorFuncsMap[op]
}

func detectSQLiOperatorEval(target Value, _ Value) (bool, string, error) {
	// TODO let IsSQLi take byte array, for fewer conversions
	found, fingerprint := li.IsSQLi(target.string())
	return found, fingerprint, nil
}

func detectXSSOperatorEval(target Value, _ Value) (bool, string, error) {
	// TODO let IsXSS take byte array, for fewer conversions
	found := li.IsXSS(target.string())
	return found, "", nil
}

func equalOperatorEval(target Value, value Value) (bool, string, error) {
	return target.equal(value), "", nil
}

func greaterOrEqualOperatorEval(target Value, value Value) (bool, string, error) {
	// TODO also support this operator for non-int values. I think ModSec 3 falls back to string lengths in that case. See CRS rule 920370.

	targetInt, ok := target.int()
	if !ok {
		return false, "", nil
	}

	valueInt, ok := value.int()
	if !ok {
		return false, "", nil
	}

	return targetInt >= valueInt, "", nil
}

func greaterThanOperatorEval(target Value, value Value) (bool, string, error) {
	// TODO also support this operator for non-int values. I think ModSec 3 falls back to string lengths in that case. See CRS rule 920370.

	targetInt, ok := target.int()
	if !ok {
		return false, "", nil
	}

	valueInt, ok := value.int()
	if !ok {
		return false, "", nil
	}

	return targetInt > valueInt, "", nil
}

func lessOrEqualOperatorEval(target Value, value Value) (bool, string, error) {
	// TODO also support this operator for non-int values. I think ModSec 3 falls back to string lengths in that case. See CRS rule 920370.

	targetInt, ok := target.int()
	if !ok {
		return false, "", nil
	}

	valueInt, ok := value.int()
	if !ok {
		return false, "", nil
	}

	return targetInt <= valueInt, "", nil
}

func lessThanOperatorEval(target Value, value Value) (bool, string, error) {
	// TODO also support this operator for non-int values. I think ModSec 3 falls back to string lengths in that case. See CRS rule 920370.

	targetInt, ok := target.int()
	if !ok {
		return false, "", nil
	}

	valueInt, ok := value.int()
	if !ok {
		return false, "", nil
	}

	return targetInt <= valueInt, "", nil
}

func beginsWithOperatorEval(target Value, value Value) (bool, string, error) {
	return bytes.HasPrefix(target.bytes(), value.bytes()), "", nil
}

func endsWithOperatorEval(target Value, value Value) (bool, string, error) {
	return bytes.HasSuffix(target.bytes(), value.bytes()), "", nil
}

func containsOperatorEval(target Value, value Value) (bool, string, error) {
	return bytes.Contains(target.bytes(), value.bytes()), "", nil
}

func containsWordOperatorEval(target Value, value Value) (bool, string, error) {
	bb := value.bytes()
	buf := make([]byte, 0, len(bb)+2)
	buf = append(buf, ' ')
	buf = append(buf, bb...)
	buf = append(buf, ' ')
	return bytes.Contains(target.bytes(), buf), "", nil
}

func strEqOperatorEval(target Value, value Value) (bool, string, error) {
	return target.equal(value), "", nil
}

func wordListSearchOperatorEval(target Value, value Value) (bool, string, error) {
	targetBytes := target.bytes()

	words := bytes.Split(value.bytes(), []byte{' '})
	for _, w := range words {
		// TODO should this be case insensitive? (bytes.EqualFold)
		if bytes.Equal(targetBytes, w) {
			return true, "", nil
		}
	}

	return false, "", nil
}

// Note that this operator-function is only used during late scanning, when scanning for or in a variable.
// Most regex rules are not based on a variable, and can therefore be scanned during request scanning.
func rxOperatorEval(actual Value, expected Value) (bool, string, error) {
	rx, err := regexp.Compile(expected.string())
	if err != nil {
		return false, "", err
	}

	captureGroups := rx.FindSubmatch(actual.bytes())
	// TODO find a way to return the capture groups up so they can be put in TX.1, etc.
	if len(captureGroups) > 0 {
		return true, string(captureGroups[0]), nil
	}

	return false, "", nil
}
