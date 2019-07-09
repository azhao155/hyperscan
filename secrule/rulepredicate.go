package secrule

import (
	"fmt"
	"strings"
)

// RulePredicate that determines the action to be taken
type RulePredicate struct {
	Targets         []string
	ExceptTargets   []string // ExceptTargets are the targets that are exempt/excluded from being matched.
	Op              Operator
	OpFunc          operatorFunc
	Neg             bool
	Val             string
	valMacroMatches [][]string
}

//example to show usage - subject to change as other components get written
func (rp *RulePredicate) eval(perRequestEnv envMap) (bool, string, error) {
	for _, target := range rp.Targets {
		val, err := expandMacros(rp.Val, perRequestEnv, rp.valMacroMatches)
		if err != nil {
			return false, "", err
		}

		//TODO: Support more variables
		variable := ""
		if isCollection(target) {
			key := strings.Replace(target, ":", ".", 1)

			varObj, ok := perRequestEnv.get(key)
			if !ok {
				return false, "", fmt.Errorf("Target %s not found in env map", key)
			}

			variable = varObj.ToString()
		}

		result, output, err := rp.OpFunc(variable, val)
		if err != nil {
			return result, "", err
		}

		if rp.Neg {
			result = !result
		}

		if result {
			return result, output, nil
		}
	}
	return false, "", nil
}

// Substitute variable macros of the type %{variable_name} with actual values
func expandMacros(s string, perRequestEnv envMap, matches [][]string) (string, error) {

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

func isCollection(target string) bool {
	//TODO: Add more prefixes
	return strings.HasPrefix(target, "TX:")
}
