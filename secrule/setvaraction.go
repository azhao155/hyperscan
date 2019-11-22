package secrule

import (
	"fmt"
	"strconv"
)

func executeSetVarAction(sv *SetVarAction, perRequestEnv environment) (err error) {
	// Eval variable
	variable, err := expandMacros(sv.variable, perRequestEnv, sv.varMacroMatches)
	if err != nil {
		return
	}

	// Eval value
	value, err := expandMacros(sv.value, perRequestEnv, sv.valMacroMatches)
	if err != nil {
		return
	}

	// Eval operator
	switch sv.operator {
	case set:
		perRequestEnv.set(variable, &stringObject{Value: value})
	case increment, decrement:
		if err = performNumericalOperation(variable, sv.operator, value, perRequestEnv); err != nil {
			return
		}
	case deleteVar:
		perRequestEnv.delete(variable)
	default:
		err = fmt.Errorf("Unsupported operator:%d for setvar operation", sv.operator)
		return
	}

	return
}

func performNumericalOperation(variable string, op setvarActionOperator, value string, perRequestEnv environment) error {
	curr, ok := perRequestEnv.get(variable)
	if !ok {
		return fmt.Errorf("setvar: attempted use of uninitialized per request state variable %s", variable)
	}

	// Convert string setting to int for future numeric operations
	switch curr.(type) {
	case *stringObject:
		currValue, err := strconv.Atoi(curr.ToString())
		if err != nil {
			return err
		}
		curr = &integerObject{Value: currValue}
	}

	currInt, ok := curr.(*integerObject)
	if !ok {
		return fmt.Errorf("Integer setting not found for key %s", variable)
	}

	// TODO: value could be potentially stored as an integer setting (handle macros, digit only strings)
	step, err := strconv.Atoi(value)
	if err != nil {
		return err
	}

	switch op {
	case increment:
		currInt.Incr(step)
	case decrement:
		currInt.Decr(step)
	}

	perRequestEnv.set(variable, currInt)
	return nil
}
