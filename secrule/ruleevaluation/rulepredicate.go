package ruleevaluation

import (
	sr "azwaf/secrule"
	ast "azwaf/secrule/ast"

	"fmt"
	"strings"
)

func eval(rp ast.RulePredicate, target ast.Target, scanResults *sr.ScanResults, perRequestEnv sr.Environment) (result bool, match sr.Match, err error) {
	opFunc := toOperatorFunc(rp.Op)
	if opFunc == nil {
		return false, sr.Match{}, fmt.Errorf("unsupported operator: %v", rp.Op)
	}

	expectedVal := perRequestEnv.ExpandMacros(rp.Val)

	var actualVal ast.Value
	if target.Name == ast.TargetTx {
		if target.IsRegexSelector {
			vv := perRequestEnv.GetTxVarsViaRegexSelector(target.Selector)

			if target.IsCount {
				actualVal = ast.Value{ast.IntToken(len(vv))}
			} else {
				return evalCollection(rp, target, expectedVal, vv, opFunc)
			}
		} else {
			if target.IsCount {
				actualVal = ast.Value{ast.IntToken(0)}
				if v := perRequestEnv.Get(ast.EnvVarTx, target.Selector); v != nil {
					actualVal = ast.Value{ast.IntToken(1)}
				}
			} else {
				varObj := perRequestEnv.Get(ast.EnvVarTx, target.Selector)
				if varObj == nil {
					return false, sr.Match{}, fmt.Errorf("transaction variable %s was not set", target.Selector)
				}
				actualVal = varObj
			}
		}
	} else if target.IsCount {
		actualVal = ast.Value{ast.IntToken(scanResults.TargetsCount[target])}
	} else if target.Name == ast.TargetMatchedVar {
		actualVal = perRequestEnv.Get(ast.EnvVarMatchedVar, "")
	} else if target.Name == ast.TargetMatchedVars {
		return evalCollection(rp, target, expectedVal, perRequestEnv.GetCollection(ast.EnvVarMatchedVars), opFunc)
	} else if target.Name == ast.TargetMatchedVarName {
		actualVal = perRequestEnv.Get(ast.EnvVarMatchedVarName, "")
	} else if target.Name == ast.TargetMatchedVarsNames {
		return evalCollection(rp, target, expectedVal, perRequestEnv.GetCollection(ast.EnvVarMatchedVarNames), opFunc)
	} else if target.Name == ast.TargetRequestLine {
		actualVal = perRequestEnv.Get(ast.EnvVarRequestLine, "")
	} else if target.Name == ast.TargetRequestMethod {
		actualVal = perRequestEnv.Get(ast.EnvVarRequestMethod, "")
	} else if target.Name == ast.TargetRequestProtocol {
		actualVal = perRequestEnv.Get(ast.EnvVarRequestProtocol, "")
	} else if target.Name == ast.TargetRequestHeaders && strings.EqualFold(target.Selector, "host") {
		actualVal = perRequestEnv.Get(ast.EnvVarRequestHeaders, "host")
	} else if target.Name == ast.TargetReqbodyProcessor {
		actualVal = perRequestEnv.Get(ast.EnvVarReqbodyProcessor, "")
	}

	result, output, err := opFunc(actualVal, expectedVal)
	if err != nil {
		result = false
		return
	}

	match = simpleMatchFromString(output, actualVal.Bytes(), target.Name)
	return
}

func evalCollection(rp ast.RulePredicate, target ast.Target, expectedVal ast.Value, values []ast.Value, opFunc operatorFunc) (result bool, match sr.Match, err error) {
	for _, actualVal := range values {
		var output string
		result, output, err = opFunc(actualVal, expectedVal)
		if err != nil {
			result = false
			return
		}

		if result == true {
			match = simpleMatchFromString(output, actualVal.Bytes(), target.Name)
			return
		}
	}

	return false, sr.Match{}, nil
}

func simpleMatchFromString(data string, entireField []byte, targetName ast.TargetName) sr.Match {
	// TODO can this be done with fewer conversions?
	o := []byte(data)
	return sr.Match{
		Data:               o,
		CaptureGroups:      [][]byte{o}, // TODO in the @rx case, this isn't currently actually the capture groups...
		EntireFieldContent: entireField,
		TargetName:         targetName,
	}
}
