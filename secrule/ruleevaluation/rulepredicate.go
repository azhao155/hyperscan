package ruleevaluation

import (
	sr "azwaf/secrule"
	ast "azwaf/secrule/ast"
	tr "azwaf/secrule/transformations"
	"strconv"

	"fmt"
	"strings"
)

func eval(rp ast.RulePredicate, target ast.Target, transformations []ast.Transformation, scanResults *sr.ScanResults, perRequestEnv sr.Environment) (result bool, match sr.Match, err error) {
	opFunc := toOperatorFunc(rp.Op)
	if opFunc == nil {
		return false, sr.Match{}, fmt.Errorf("unsupported operator: %v", rp.Op)
	}

	expectedVal := perRequestEnv.ExpandMacros(rp.Val)

	var actualVal ast.Value
	var actualValCollection []ast.Value
	if target.Name == ast.TargetTx {
		if target.IsRegexSelector {
			vv := perRequestEnv.GetTxVarsViaRegexSelector(target.Selector)

			if target.IsCount {
				actualVal = ast.Value{ast.IntToken(len(vv))}
			} else {
				actualValCollection = vv
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
		actualValCollection = perRequestEnv.GetCollection(ast.EnvVarMatchedVars)
	} else if target.Name == ast.TargetMatchedVarName {
		actualVal = perRequestEnv.Get(ast.EnvVarMatchedVarName, "")
	} else if target.Name == ast.TargetMatchedVarsNames {
		actualValCollection = perRequestEnv.GetCollection(ast.EnvVarMatchedVarNames)
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
	} else if target.Name == ast.TargetReqbodyError {
		actualVal = perRequestEnv.Get(ast.EnvVarReqbodyProcessorError, "")
	} else if target.Name == ast.TargetMultipartBoundaryQuoted {
		actualVal = perRequestEnv.Get(ast.EnvVarMultipartBoundaryQuoted, "")
	} else if target.Name == ast.TargetMultipartBoundaryWhitespace {
		actualVal = perRequestEnv.Get(ast.EnvVarMultipartBoundaryWhitespace, "")
	} else if target.Name == ast.TargetMultipartDataAfter {
		actualVal = perRequestEnv.Get(ast.EnvVarMultipartDataAfter, "")
	} else if target.Name == ast.TargetMultipartDataBefore {
		actualVal = perRequestEnv.Get(ast.EnvVarMultipartDataBefore, "")
	} else if target.Name == ast.TargetMultipartFileLimitExceeded {
		actualVal = perRequestEnv.Get(ast.EnvVarMultipartFileLimitExceeded, "")
	} else if target.Name == ast.TargetMultipartHeaderFolding {
		actualVal = perRequestEnv.Get(ast.EnvVarMultipartHeaderFolding, "")
	} else if target.Name == ast.TargetMultipartInvalidHeaderFolding {
		actualVal = perRequestEnv.Get(ast.EnvVarMultipartInvalidHeaderFolding, "")
	} else if target.Name == ast.TargetMultipartInvalidQuoting {
		actualVal = perRequestEnv.Get(ast.EnvVarMultipartInvalidQuoting, "")
	} else if target.Name == ast.TargetMultipartLfLine {
		actualVal = perRequestEnv.Get(ast.EnvVarMultipartLfLine, "")
	} else if target.Name == ast.TargetMultipartMissingSemicolon {
		actualVal = perRequestEnv.Get(ast.EnvVarMultipartMissingSemicolon, "")
	} else if target.Name == ast.TargetMultipartStrictError {
		actualVal = perRequestEnv.Get(ast.EnvVarMultipartStrictError, "")
	} else if target.Name == ast.TargetMultipartUnmatchedBoundary {
		actualVal = perRequestEnv.Get(ast.EnvVarMultipartUnmatchedBoundary, "")
	}

	if len(actualValCollection) == 0 {
		actualValCollection = []ast.Value{actualVal}
	}

	return evalCollection(rp, target, expectedVal, actualValCollection, transformations, opFunc)
}

func evalCollection(rp ast.RulePredicate, target ast.Target, expectedVal ast.Value, values []ast.Value, transformations []ast.Transformation, opFunc operatorFunc) (result bool, match sr.Match, err error) {
	for _, actualVal := range values {
		// Apply transformations to actualVal if this was not an integer value.
		_, isInt := actualVal.Int()
		if !isInt {
			s := tr.ApplyTransformations(actualVal.String(), transformations)
			n, atoierr := strconv.Atoi(s)
			if atoierr == nil {
				actualVal = ast.Value{ast.IntToken(n)}
			} else {
				actualVal = ast.Value{ast.StringToken(s)}
			}
		}

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
