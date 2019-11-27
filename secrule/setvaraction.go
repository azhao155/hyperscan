package secrule

import (
	"fmt"
	"strings"
)

func executeSetVarAction(sv *SetVarAction, perRequestEnv environment) (err error) {
	variableName := strings.ToLower(sv.variable.expandMacros(perRequestEnv).string())
	value := sv.value.expandMacros(perRequestEnv)

	// Eval operator
	switch sv.operator {
	case set:
		perRequestEnv.set(variableName, value)
	case increment, decrement:
		if err = performNumericalOperation(variableName, sv.operator, value, perRequestEnv); err != nil {
			return
		}
	case deleteVar:
		perRequestEnv.delete(variableName)
	default:
		err = fmt.Errorf("unsupported operator %d for setvar operation", sv.operator)
		return
	}

	return
}

func performNumericalOperation(variable string, op setvarActionOperator, value Value, perRequestEnv environment) error {
	curr, ok := perRequestEnv.get(variable)
	if !ok {
		curr = Value{IntToken(0)}
	}

	currInt, ok := curr.int()
	if !ok {
		return fmt.Errorf("variable %s was not an integer", variable)
	}

	valueInt, ok := value.int()
	if !ok {
		return fmt.Errorf("value %s was not an integer", value.string())
	}

	switch op {
	case increment:
		currInt += valueInt
	case decrement:
		currInt -= valueInt
	}

	perRequestEnv.set(variable, Value{IntToken(currInt)})
	return nil
}
