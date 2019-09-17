package customrule

import (
	"azwaf/secrule"
	"strings"
)

func (rl *ruleLoader) toOperatorFunc(op string) secrule.CustomOpCallBackFunc {
	var customOperatorFuncsMap = map[string]secrule.CustomOpCallBackFunc{
		"GeoMatch": rl.geoMatchOperatorEval,
	}

	return customOperatorFuncsMap[op]
}

func (rl *ruleLoader) geoMatchOperatorEval(target string, value string) (match bool, matchVal string, err error) {
	countryCode := rl.geoDB.GeoLookup(target)
	match = strings.EqualFold(value, countryCode)
	matchVal = countryCode
	return
}
