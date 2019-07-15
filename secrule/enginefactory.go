package secrule

import (
	"azwaf/waf"
	"fmt"
	log "github.com/sirupsen/logrus"
)

// NewEngineFactory creates a factory that can create SecRule engines.
func NewEngineFactory(rl RuleLoader, rsf ReqScannerFactory, re RuleEvaluator, reslog ResultsLogger) waf.SecRuleEngineFactory {
	return &engineFactoryImpl{rl, rsf, re, reslog}
}

type engineFactoryImpl struct {
	ruleLoader        RuleLoader
	reqScannerFactory ReqScannerFactory
	ruleEvaluator     RuleEvaluator
	resultsLogger     ResultsLogger
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

	engine = &engineImpl{statements, reqScanner, f.ruleEvaluator, f.resultsLogger}
	return
}
