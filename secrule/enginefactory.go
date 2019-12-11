package secrule

import (
	"azwaf/waf"
	"fmt"

	"github.com/rs/zerolog"
)

// NewEngineFactory creates a factory that can create SecRule engines.
func NewEngineFactory(logger zerolog.Logger, rl RuleLoader, rsf ReqScannerFactory, ref RuleEvaluatorFactory) waf.SecRuleEngineFactory {
	return &engineFactoryImpl{
		logger:               logger,
		ruleLoader:           rl,
		reqScannerFactory:    rsf,
		ruleEvaluatorFactory: ref,
	}
}

type engineFactoryImpl struct {
	logger               zerolog.Logger
	ruleLoader           RuleLoader
	reqScannerFactory    ReqScannerFactory
	ruleEvaluatorFactory RuleEvaluatorFactory
}

func (f *engineFactoryImpl) NewEngine(config waf.SecRuleConfig) (engine waf.SecRuleEngine, err error) {
	ruleSetID := waf.RuleSetID(config.RuleSetID())
	f.logger.Info().Str("ruleSet", string(ruleSetID)).Msg("Loading rules")

	statements, err := f.ruleLoader.Rules(ruleSetID)
	if err != nil {
		err = fmt.Errorf("failed to load ruleset %v: %v", ruleSetID, err)
		return
	}

	engine, err = NewEngine(statements, f.reqScannerFactory, f.ruleEvaluatorFactory, ruleSetID)
	if err != nil {
		return
	}

	return
}
