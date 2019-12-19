package ruleevaluation

import (
	sr "azwaf/secrule"
	ast "azwaf/secrule/ast"

	"github.com/rs/zerolog"
)

// NewRuleEvaluatorFactory creates a NewRuleEvaluatorFactory instance.
func NewRuleEvaluatorFactory() sr.RuleEvaluatorFactory {
	return &ruleEvaluatorFactoryImpl{}
}

type ruleEvaluatorFactoryImpl struct {
}

func (r *ruleEvaluatorFactoryImpl) NewRuleEvaluator(logger zerolog.Logger, perRequestEnv sr.Environment, statements []ast.Statement, scanResults *sr.ScanResults, triggeredCb sr.RuleEvaluatorTriggeredCb) sr.RuleEvaluator {
	return &ruleEvaluatorImpl{
		logger:        logger,
		perRequestEnv: perRequestEnv,
		statements:    statements,
		scanResults:   scanResults,
		triggeredCb:   triggeredCb,
	}
}
