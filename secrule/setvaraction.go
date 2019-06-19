package secrule

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SetvarAction captures the CRS setvar action
type SetvarAction struct {
	//TODO: potential optimization, variable and value could be stored as a list of objects (especially in case of macros)
	variable        string
	operator        setvarActionOperator
	value           string
	varMacroMatches [][]string
	valMacroMatches [][]string
}

var parameterRegex = regexp.MustCompile(`!?(?P<variable>[^=]+)(?P<operator>=[+-]?)?(?P<value>.+)?`)
var variableRegex = regexp.MustCompile(`%{(?P<variable>[^}]+)}`)

// NewSetvarAction creates a secrule.SetVarAction.
func NewSetvarAction(parameter string) (*SetvarAction, error) {
	matches := parameterRegex.FindStringSubmatch(parameter)
	if matches == nil {
		return nil, fmt.Errorf("Unsupported parameter:%s for setvar operation", parameter)
	}

	// TODO: potential optimization (replace map with variables)
	result := findStringSubmatchMap(parameterRegex, parameter)
	if parameter[0] == '!' {
		result["operator"] = "!"
	}

	// Default values
	if result["operator"] == "" {
		result["operator"] = "="
	}

	if result["value"] == "" {
		result["value"] = "1"
	}

	op, err := toSetvarOperator(result["operator"])
	if err != nil {
		return nil, err
	}

	varMacroMatches := variableRegex.FindAllStringSubmatch(result["variable"], -1)
	valMacroMatches := variableRegex.FindAllStringSubmatch(result["value"], -1)

	return &(SetvarAction{
		variable:        result["variable"],
		operator:        op,
		value:           result["value"],
		varMacroMatches: varMacroMatches,
		valMacroMatches: valMacroMatches}), nil
}

// Execute performs the setvar action
func (sv SetvarAction) Execute(perRequestEnv envMap) error {
	// Eval variable
	variable, err := expandVars(sv.variable, perRequestEnv, sv.varMacroMatches)
	if err != nil {
		return err
	}

	// Eval value
	value, err := expandVars(sv.value, perRequestEnv, sv.valMacroMatches)
	if err != nil {
		return err
	}

	// Eval operator
	switch sv.operator {
	case set:
		perRequestEnv.set(variable, &stringObject{Value: value})
	case increment, decrement:
		if err := performNumericalOperation(variable, sv.operator, value, perRequestEnv); err != nil {
			return err
		}
	case deleteVar:
		perRequestEnv.delete(variable)
	default:
		return fmt.Errorf("Unsupported operator:%d for setvar operation", sv.operator)
	}

	return nil
}

// Substitute variable placeholders of the type %{variable_name} with actual values
func expandVars(s string, perRequestEnv envMap, matches [][]string) (string, error) {

	// Replace placeholders
	for i := 0; i < len(matches); i++ {
		newVal, ok := perRequestEnv.get(matches[i][1])
		if !ok {
			return "", fmt.Errorf("setvar: attempted use of uninitialized request state variable %s", matches[i][1])
		}

		// Replace full match with variable value
		s = strings.Replace(s, matches[i][0], newVal.ToString(), 1)
	}
	return s, nil
}

func performNumericalOperation(variable string, op setvarActionOperator, value string, perRequestEnv envMap) error {
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

func findStringSubmatchMap(r *regexp.Regexp, str string) map[string]string {
	match := r.FindStringSubmatch(str)
	if match == nil {
		return nil
	}

	submatchMap := make(map[string]string)
	for i, name := range r.SubexpNames() {
		if i != 0 {
			submatchMap[name] = match[i]
		}
	}

	return submatchMap
}
