package secrule

import (
	"fmt"
	"strconv"
	"strings"
)

func (rp *RulePredicate) eval(scanResults *ScanResults, perRequestEnv envMap) (result bool, output string, err error) {
	for _, target := range rp.Targets {
		expectedVal, err := expandMacros(rp.Val, perRequestEnv, rp.valMacroMatches)
		if err != nil {
			return false, "", err
		}

		actualVal := ""
		const transactionVariableCollectionTargetName string = "TX"
		if target.Name == transactionVariableCollectionTargetName {
			if target.IsCount {
				// Variable counting
				actualVal = "0"
				if target.Selector != "" {
					key := target.Name + "." + target.Selector
					if perRequestEnv.hasKey(key) {
						actualVal = "1"
					}
				}
			} else {
				key := target.Name + "." + target.Selector

				varObj, ok := perRequestEnv.get(key)
				if !ok {
					return false, "", fmt.Errorf("Target %s not found in env map", key)
				}

				actualVal = varObj.ToString()
			}
		} else if target.IsCount {
			actualVal = strconv.Itoa(scanResults.targetsCount[target])
		} else {
			// TODO Support ways of getting actualVal
		}

		opFunc := toOperatorFunc(rp.Op)
		result, output, err = opFunc(actualVal, expectedVal)

		if err != nil {
			return result, "", err
		}

		if result {
			return result, output, nil
		}
	}
	return false, "", nil
}

// Substitute variable macros of the type %{variable_name} with actual values
func expandMacros(s string, perRequestEnv envMap, matches [][]string) (string, error) {
	// TODO potential optimization: this could return object instead of string, so we could potentially return an integer if the entire input string was a macro (very common)

	// Replace placeholders
	for i := 0; i < len(matches); i++ {
		newVal, ok := perRequestEnv.get(matches[i][1])
		if !ok {
			return "", fmt.Errorf("attempted use of uninitialized request state variable %s", matches[i][1])
		}

		// Replace full match with variable value
		s = strings.Replace(s, matches[i][0], newVal.ToString(), 1)
	}
	return s, nil
}
