package secrule

import "fmt"

// RuleSetID identifies which rule set to initialize the engine with.
type RuleSetID string

// EngineFactory creates a secrule.Engine. This makes mocking possible when testing.
type EngineFactory interface {
	NewEngine(r RuleSetID) (Engine, error)
}

// NewEngineFactory creates a secrule.EngineFactory.
func NewEngineFactory(rl RuleLoader, rsf ReqScannerFactory) EngineFactory {
	return &engineFactoryImpl{rl, rsf}
}

type engineFactoryImpl struct {
	ruleLoader        RuleLoader
	reqScannerFactory ReqScannerFactory
}

func (f *engineFactoryImpl) NewEngine(ruleSetID RuleSetID) (engine Engine, err error) {
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
