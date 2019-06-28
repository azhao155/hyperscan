package secrule

import (
	"azwaf/waf"
	"fmt"
)

// NewEngineFactory creates a factory that can create SecRule engines.
func NewEngineFactory(rl RuleLoader, rsf ReqScannerFactory) waf.SecRuleEngineFactory {
	return &engineFactoryImpl{rl, rsf}
}

type engineFactoryImpl struct {
	ruleLoader        RuleLoader
	reqScannerFactory ReqScannerFactory
}

func (f *engineFactoryImpl) NewEngine(ruleSetID waf.RuleSetID) (engine waf.SecRuleEngine, err error) {
	rules, err := f.ruleLoader.Rules(ruleSetID)
	if err != nil {
		err = fmt.Errorf("failed to load ruleset %v: %v", ruleSetID, err)
		return
	}

	reqScanner, err := f.reqScannerFactory.NewReqScanner(rules)
	if err != nil {
		err = fmt.Errorf("failed to create request scanner: %v", err)
		return
	}

	engine = &engineImpl{rules, reqScanner}
	return
}
