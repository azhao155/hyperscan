package secrule

import (
	"fmt"
	"strings"
)

func (rp *RulePredicate) eval(target Target, scanResults *ScanResults, perRequestEnv *environment) (result bool, match Match, err error) {
	opFunc := toOperatorFunc(rp.Op)
	if opFunc == nil {
		return false, Match{}, fmt.Errorf("unsupported operator: %v", rp.Op)
	}

	expectedVal := rp.Val.expandMacros(perRequestEnv)

	var actualVal Value
	if target.Name == TargetTx {
		if target.IsCount {
			// Variable counting
			actualVal = Value{IntToken(0)}
			if target.Selector != "" {
				key := strings.ToLower("tx." + target.Selector)
				if perRequestEnv.hasKey(key) {
					actualVal = Value{IntToken(1)}
				}
			}
		} else {
			key := strings.ToLower("tx." + target.Selector)

			varObj, ok := perRequestEnv.get(key)
			if !ok {
				return false, Match{}, fmt.Errorf("target %s not found in env map", key)
			}

			actualVal = varObj
		}
	} else if target.IsCount {
		actualVal = Value{IntToken(scanResults.targetsCount[target])}
	} else if target.Name == TargetMatchedVar {
		actualVal = perRequestEnv.matchedVar
	} else if target.Name == TargetMatchedVars {
		return rp.evalCollection(target, expectedVal, perRequestEnv.matchedVars, opFunc)
	} else if target.Name == TargetMatchedVarName {
		actualVal = perRequestEnv.matchedVarName
	} else if target.Name == TargetMatchedVarsNames {
		return rp.evalCollection(target, expectedVal, perRequestEnv.matchedVarNames, opFunc)
	} else if target.Name == TargetRequestLine {
		actualVal = perRequestEnv.requestLine
	} else if target.Name == TargetRequestMethod {
		actualVal = perRequestEnv.requestMethod
	} else if target.Name == TargetRequestProtocol {
		actualVal = perRequestEnv.requestProtocol
	} else if target.Name == TargetRequestHeaders && strings.EqualFold(target.Selector, "host") {
		actualVal = perRequestEnv.hostHeader
	}

	result, output, err := opFunc(actualVal, expectedVal)
	if err != nil {
		result = false
		return
	}

	match = simpleMatchFromString(output, actualVal.bytes(), target.Name)
	return
}

func (rp *RulePredicate) evalCollection(target Target, expectedVal Value, values []Value, opFunc operatorFunc) (result bool, match Match, err error) {
	for _, actualVal := range values {
		var output string
		result, output, err = opFunc(actualVal, expectedVal)
		if err != nil {
			result = false
			return
		}

		if result == true {
			match = simpleMatchFromString(output, actualVal.bytes(), target.Name)
			return
		}
	}

	return false, Match{}, nil
}

func simpleMatchFromString(data string, entireField []byte, targetName TargetName) Match {
	// TODO can this be done with fewer conversions?
	o := []byte(data)
	return Match{
		Data:               o,
		CaptureGroups:      [][]byte{o}, // TODO in the @rx case, this isn't currently actually the capture groups...
		EntireFieldContent: entireField,
		TargetName:         targetName,
	}
}
