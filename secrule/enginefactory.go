package secrule

import (
	"azwaf/waf"
	"fmt"
	log "github.com/sirupsen/logrus"
)

// NewEngineFactory creates a factory that can create SecRule engines.
func NewEngineFactory(rl RuleLoader, rsf ReqScannerFactory, ref RuleEvaluatorFactory) waf.SecRuleEngineFactory {
	return &engineFactoryImpl{rl, rsf, ref}
}

type engineFactoryImpl struct {
	ruleLoader           RuleLoader
	reqScannerFactory    ReqScannerFactory
	ruleEvaluatorFactory RuleEvaluatorFactory
}

func (f *engineFactoryImpl) NewEngine(config waf.SecRuleConfig) (engine waf.SecRuleEngine, err error) {
	ruleSetID := waf.RuleSetID(config.RuleSetID())
	log.WithFields(log.Fields{"ruleSet": ruleSetID}).Info("Loading rules")

	statements, err := f.ruleLoader.Rules(ruleSetID)
	if err != nil {
		err = fmt.Errorf("failed to load ruleset %v: %v", ruleSetID, err)
		return
	}

	reqScanner, err := f.reqScannerFactory.NewReqScanner(statements)
	if err != nil {
		err = fmt.Errorf("failed to create request scanner: %v", err)
		return
	}

	engine = &engineImpl{statements, reqScanner, f.ruleEvaluatorFactory.NewRuleEvaluator(newEnvMap())}
	return
}
