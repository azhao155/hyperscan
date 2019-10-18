package secrule

import (
	"fmt"
	"strings"
)

func (rp *RulePredicate) eval(perRequestEnv envMap) (result bool, output string, err error) {
	for _, target := range rp.Targets {
		val, err := expandMacros(rp.Val, perRequestEnv, rp.valMacroMatches)
		if err != nil {
			return false, "", err
		}

		//TODO: Support more variables
		variable := ""
		if target.IsCount && target.Name == "TX" {
			// Variable counting
			variable = "0"
			if target.Selector != "" {
				key := target.Name + "." + target.Selector
				if perRequestEnv.hasKey(key) {
					variable = "1"
				}
			}
		}

		if isCollection(target) && !target.IsCount {
			key := target.Name + "." + target.Selector

			varObj, ok := perRequestEnv.get(key)
			if !ok {
				return false, "", fmt.Errorf("Target %s not found in env map", key)
			}

			variable = varObj.ToString()
		}

		opFunc := toOperatorFunc(rp.Op)
		result, output, err = opFunc(variable, val)

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

func isCollection(target Target) bool {
	//TODO: Add more ways of deciding whether collection
	return target.Name == "TX"
}
