package ruleevaluation

import (
	sr "azwaf/secrule"
	ast "azwaf/secrule/ast"

	"fmt"
	"strings"
)

func executeSetVarAction(sv *ast.SetVarAction, perRequestEnv sr.Environment) (err error) {
	variableName := strings.ToLower(perRequestEnv.ExpandMacros(sv.Variable).String())
	value := perRequestEnv.ExpandMacros(sv.Value)

	if !strings.HasPrefix(variableName, "tx.") {
		err = fmt.Errorf("unsupported variable %s for setvar operation", variableName)
		return
	}

	variableName = strings.TrimPrefix(variableName, "tx.")

	// Eval operator
	switch sv.Operator {
	case ast.Set:
		perRequestEnv.Set(ast.EnvVarTx, variableName, value)
	case ast.Increment, ast.Decrement:
		if err = performNumericalOperation(variableName, sv.Operator, value, perRequestEnv); err != nil {
			return
		}
	case ast.DeleteVar:
		perRequestEnv.Delete(ast.EnvVarTx, variableName)
	default:
		err = fmt.Errorf("unsupported operator %d for setvar operation", sv.Operator)
		return
	}

	return
}

func performNumericalOperation(variable string, op ast.SetVarActionOperator, value ast.Value, perRequestEnv sr.Environment) error {
	curr := perRequestEnv.Get(ast.EnvVarTx, variable)
	if curr == nil {
		curr = ast.Value{ast.IntToken(0)}
	}

	currInt, ok := curr.Int()
	if !ok {
		return fmt.Errorf("variable %s was not an integer", variable)
	}

	valueInt, ok := value.Int()
	if !ok {
		return fmt.Errorf("value %s was not an integer", value.String())
	}

	switch op {
	case ast.Increment:
		currInt += valueInt
	case ast.Decrement:
		currInt -= valueInt
	}

	perRequestEnv.Set(ast.EnvVarTx, variable, ast.Value{ast.IntToken(currInt)})
	return nil
}
