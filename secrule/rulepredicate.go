package secrule

import (
	"fmt"
	"strings"
)

func (rp *RulePredicate) eval(target Target, scanResults *ScanResults, perRequestEnv *environment) (result bool, match Match, err error) {
	opFunc := toOperatorFunc(rp.Op)
	if opFunc == nil {
		return false, Match{}, fmt.Errorf("unsupported operator: %v", rp.Op)
	}

	expectedVal := rp.Val.expandMacros(perRequestEnv)

	var actualVal Value
	if target.Name == TargetTx {
		if target.IsRegexSelector {
			vv := perRequestEnv.getTxVarsViaRegexSelector(target.Selector)

			if target.IsCount {
				actualVal = Value{IntToken(len(vv))}
			} else {
				return rp.evalCollection(target, expectedVal, vv, opFunc)
			}
		} else {
			if target.IsCount {
				actualVal = Value{IntToken(0)}
				if v := perRequestEnv.get(EnvVarTx, target.Selector); v != nil {
					actualVal = Value{IntToken(1)}
				}
			} else {
				varObj := perRequestEnv.get(EnvVarTx, target.Selector)
				if varObj == nil {
					return false, Match{}, fmt.Errorf("transaction variable %s was not set", target.Selector)
				}
				actualVal = varObj
			}
		}
	} else if target.IsCount {
		actualVal = Value{IntToken(scanResults.targetsCount[target])}
	} else if target.Name == TargetMatchedVar {
		actualVal = perRequestEnv.get(EnvVarMatchedVar, "")
	} else if target.Name == TargetMatchedVars {
		return rp.evalCollection(target, expectedVal, perRequestEnv.getCollection(EnvVarMatchedVars), opFunc)
	} else if target.Name == TargetMatchedVarName {
		actualVal = perRequestEnv.get(EnvVarMatchedVarName, "")
	} else if target.Name == TargetMatchedVarsNames {
		return rp.evalCollection(target, expectedVal, perRequestEnv.getCollection(EnvVarMatchedVarNames), opFunc)
	} else if target.Name == TargetRequestLine {
		actualVal = perRequestEnv.get(EnvVarRequestLine, "")
	} else if target.Name == TargetRequestMethod {
		actualVal = perRequestEnv.get(EnvVarRequestMethod, "")
	} else if target.Name == TargetRequestProtocol {
		actualVal = perRequestEnv.get(EnvVarRequestProtocol, "")
	} else if target.Name == TargetRequestHeaders && strings.EqualFold(target.Selector, "host") {
		actualVal = perRequestEnv.get(EnvVarRequestHeaders, "host")
	} else if target.Name == TargetReqbodyProcessor {
		actualVal = perRequestEnv.get(EnvVarReqbodyProcessor, "")
	}

	result, output, err := opFunc(actualVal, expectedVal)
	if err != nil {
		result = false
		return
	}

	match = simpleMatchFromString(output, actualVal.bytes(), target.Name)
	return
}

func (rp *RulePredicate) evalCollection(target Target, expectedVal Value, values []Value, opFunc operatorFunc) (result bool, match Match, err error) {
	for _, actualVal := range values {
		var output string
		result, output, err = opFunc(actualVal, expectedVal)
		if err != nil {
			result = false
			return
		}

		if result == true {
			match = simpleMatchFromString(output, actualVal.bytes(), target.Name)
			return
		}
	}

	return false, Match{}, nil
}

func simpleMatchFromString(data string, entireField []byte, targetName TargetName) Match {
	// TODO can this be done with fewer conversions?
	o := []byte(data)
	return Match{
		Data:               o,
		CaptureGroups:      [][]byte{o}, // TODO in the @rx case, this isn't currently actually the capture groups...
		EntireFieldContent: entireField,
		TargetName:         targetName,
	}
}
