package customrule

import (
	"azwaf/secrule"
	"azwaf/waf"
	"fmt"
	"github.com/rs/zerolog"
)

// NewEngineFactory creates a custom rule engine factory
func NewEngineFactory(logger zerolog.Logger, rl RuleLoader, rsf secrule.ReqScannerFactory, re secrule.RuleEvaluator) waf.CustomRuleEngineFactory {
	return &engineFactoryImpl{
		logger:            logger,
		ruleLoader:		   rl,
		reqScannerFactory: rsf,
		ruleEvaluator:     re,
	}
}

type engineFactoryImpl struct {
	logger            zerolog.Logger
	ruleLoader        RuleLoader
	reqScannerFactory secrule.ReqScannerFactory
	ruleEvaluator     secrule.RuleEvaluator
}

func (f *engineFactoryImpl) NewEngine(config waf.CustomRuleConfig) (engine waf.CustomRuleEngine, err error) {
	e := &engineImpl{}

	stmts, err := f.ruleLoader.GetSecRules(f.logger, "{}")
	if err != nil {
		err = fmt.Errorf("failed to load custom rules, error: %v", err)
		return
	}

	rl := &secRuleEngineResultsLoggerAdapter{}
	e.underlyingSecRuleEngine, err = secrule.NewEngine(stmts, f.reqScannerFactory, f.ruleEvaluator, rl)
	if err != nil {
		return
	}

	engine = e
	return
}
