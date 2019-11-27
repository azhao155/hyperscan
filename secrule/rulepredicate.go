package secrule

import (
	"fmt"
	"strings"
)

func (rp *RulePredicate) eval(target Target, scanResults *ScanResults, perRequestEnv environment) (result bool, match Match, err error) {
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
		actualVal = Value{StringToken(perRequestEnv.matchedVar)}
	} else if strings.EqualFold(target.Name, "matched_var_name") {
		actualVal = Value{StringToken(perRequestEnv.matchedVarName)}
	}

	opFunc := toOperatorFunc(rp.Op)
	if opFunc == nil {
		return false, Match{}, fmt.Errorf("unsupported operator: %v", rp.Op)
	}
	result, output, err := opFunc(actualVal, expectedVal)
	if err != nil {
		result = false
		return
	}

	// TODO can this be done with fewer conversions?
	o := []byte(output)
	match = Match{
		Data:               o,
		CaptureGroups:      [][]byte{o}, // TODO in the @rx case, this isn't currently actually the capture groups...
		EntireFieldContent: []byte(actualVal.bytes()),
		TargetName:         []byte(target.Name),
	}

	return
}
