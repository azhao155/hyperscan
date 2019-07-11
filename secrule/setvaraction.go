package secrule

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"regexp"
	"strconv"
)

// setVarAction captures the CRS setvar action
type setVarAction struct {
	//TODO: potential optimization, variable and value could be stored as a list of objects (especially in case of macros)
	variable        string
	operator        setvarActionOperator
	value           string
	varMacroMatches [][]string
	valMacroMatches [][]string
}

var parameterRegex = regexp.MustCompile(`!?(?P<variable>[^=]+)(?P<operator>=[+-]?)?(?P<value>.+)?`)

func newSetVarAction(parameter string) (*setVarAction, error) {
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

	varMacroMatches := variableMacroRegex.FindAllStringSubmatch(result["variable"], -1)
	valMacroMatches := variableMacroRegex.FindAllStringSubmatch(result["value"], -1)

	return &(setVarAction{
		variable:        result["variable"],
		operator:        op,
		value:           result["value"],
		varMacroMatches: varMacroMatches,
		valMacroMatches: valMacroMatches}), nil
}

func (sv setVarAction) isDisruptive() bool {
	return false
}

// execute performs the setvar action
func (sv setVarAction) execute(perRequestEnv envMap) (ar *actionResult) {
	ar = newActionResult()

	// Eval variable
	variable, err := expandMacros(sv.variable, perRequestEnv, sv.varMacroMatches)
	if err != nil {
		ar.err = err
		return
	}

	// Eval value
	value, err := expandMacros(sv.value, perRequestEnv, sv.valMacroMatches)
	if err != nil {
		ar.err = err
		return
	}

	// Eval operator
	switch sv.operator {
	case set:
		perRequestEnv.set(variable, &stringObject{Value: value})
	case increment, decrement:
		if err := performNumericalOperation(variable, sv.operator, value, perRequestEnv); err != nil {
			ar.err = err
			return
		}
	case deleteVar:
		perRequestEnv.delete(variable)
	default:
		ar.err = fmt.Errorf("Unsupported operator:%d for setvar operation", sv.operator)
		return
	}

	newValue, _ := perRequestEnv.get(variable)
	log.WithFields(log.Fields{"variable": variable, "newValue": newValue}).Trace("Executed setVarAction")

	return
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
