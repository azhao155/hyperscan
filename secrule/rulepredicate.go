package secrule

import (
	"fmt"
	"strings"
)

func (rp *RulePredicate) eval(target Target, scanResults *ScanResults, perRequestEnv environment) (result bool, match Match, err error) {
	opFunc := toOperatorFunc(rp.Op)
	if opFunc == nil {
		return false, Match{}, fmt.Errorf("unsupported operator: %v", rp.Op)
	}

	expectedVal := rp.Val.expandMacros(perRequestEnv)

	var actualVal Value
	if strings.EqualFold(target.Name, "tx") {
		if target.IsCount {
			// Variable counting
			actualVal = Value{IntToken(0)}
			if target.Selector != "" {
				key := strings.ToLower(target.Name + "." + target.Selector)
				if perRequestEnv.hasKey(key) {
					actualVal = Value{IntToken(1)}
				}
			}
		} else {
			key := strings.ToLower(target.Name + "." + target.Selector)

			varObj, ok := perRequestEnv.get(key)
			if !ok {
				return false, Match{}, fmt.Errorf("target %s not found in env map", key)
			}

			actualVal = varObj
		}
	} else if target.IsCount {
		actualVal = Value{IntToken(scanResults.targetsCount[target])}
	} else if strings.EqualFold(target.Name, "matched_var") {
		actualVal = perRequestEnv.matchedVar
	} else if strings.EqualFold(target.Name, "matched_vars") {
		return rp.evalCollection(target, expectedVal, perRequestEnv.matchedVars, opFunc)
	} else if strings.EqualFold(target.Name, "matched_var_name") {
		actualVal = perRequestEnv.matchedVarName
	} else if strings.EqualFold(target.Name, "matched_vars_names") {
		return rp.evalCollection(target, expectedVal, perRequestEnv.matchedVarNames, opFunc)
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

func simpleMatchFromString(data string, entireField []byte, targetName string) Match {
	// TODO can this be done with fewer conversions?
	o := []byte(data)
	return Match{
		Data:               o,
		CaptureGroups:      [][]byte{o}, // TODO in the @rx case, this isn't currently actually the capture groups...
		EntireFieldContent: entireField,
		TargetName:         []byte(targetName),
	}
}
