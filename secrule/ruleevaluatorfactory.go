package secrule

import "github.com/rs/zerolog"

// RuleEvaluatorFactory creates RuleEvaluator instances.
type RuleEvaluatorFactory interface {
	NewRuleEvaluator(logger zerolog.Logger, perRequestEnv *environment, statements []Statement, scanResults *ScanResults, triggeredCb RuleEvaluatorTriggeredCb) RuleEvaluator
}

// NewRuleEvaluatorFactory creates a NewRuleEvaluatorFactory instance.
func NewRuleEvaluatorFactory() RuleEvaluatorFactory {
	return &ruleEvaluatorFactoryImpl{}
}

type ruleEvaluatorFactoryImpl struct {
}

func (r *ruleEvaluatorFactoryImpl) NewRuleEvaluator(logger zerolog.Logger, perRequestEnv *environment, statements []Statement, scanResults *ScanResults, triggeredCb RuleEvaluatorTriggeredCb) RuleEvaluator {
	return &ruleEvaluatorImpl{
		logger:        logger,
		perRequestEnv: perRequestEnv,
		statements:    statements,
		scanResults:   scanResults,
		triggeredCb:   triggeredCb,
	}
}
