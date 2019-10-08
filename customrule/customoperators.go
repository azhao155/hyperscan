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
	// Example target param: "8.8.8.8:80,8.8.4.4,10.10.10.10:443".
	for _, address := range strings.Split(target, ",") {
		ip := strings.TrimSpace(strings.Split(address, ":")[0])
		for _, val := range strings.Split(value, ",") {
			countryCode := rl.geoDB.GeoLookup(ip)
			match = strings.EqualFold(val, countryCode)
			if match {
				matchVal = countryCode
				return
			}
		}
	}
	return
}
