package secrule

import (
	log "github.com/sirupsen/logrus"
)

// RuleEvaluator processes the incoming request against all parsed rules
type RuleEvaluator interface {
	Process(statements []Statement, scanResults *ScanResults) (allow bool, statusCode int, err error)
}

type ruleEvaluatorImpl struct {
	// TODO: populate initial values as part of TxState task
	perRequestEnv envMap
}

// RuleEvaluatorFactory creates RuleEvaluators.
type RuleEvaluatorFactory interface {
	NewRuleEvaluator(env envMap) (r RuleEvaluator)
}

// NewRuleEvaluatorFactory creates a RuleEvaluatorFactory.
func NewRuleEvaluatorFactory() RuleEvaluatorFactory {
	return &ruleEvaluatorFactoryImpl{newEnvMap()}
}

type ruleEvaluatorFactoryImpl struct {
	em envMap
}

// NewRuleEvaluator creates a new rule evaluator
func (ref *ruleEvaluatorFactoryImpl) NewRuleEvaluator(em envMap) (r RuleEvaluator) {
	r = &ruleEvaluatorImpl{em}
	return
}

func (r ruleEvaluatorImpl) Process(statements []Statement, scanResults *ScanResults) (bool, int, error) {
	// Comment these in until full support for &-operators in order to properly load the init conf files
	//r.perRequestEnv.set("tx.critical_anomaly_score", &integerObject{5})
	//r.perRequestEnv.set("tx.anomaly_score", &integerObject{0})
	//r.perRequestEnv.set("tx.inbound_anomaly_score_threshold", &integerObject{5})
	//r.perRequestEnv.set("tx.crs_setup_version", &integerObject{1})

	for _, stmt := range statements {
		switch stmt := stmt.(type) {
		case *Rule:
			rule := stmt
			isChainDone := false
			for curRuleItemIdx, ruleItem := range rule.Items {
				if isChainDone {
					break
				}

				log.WithFields(log.Fields{"ruleID": rule.ID, "ruleItemIdx": curRuleItemIdx}).Trace("Evaluating rule")

				matchFound := false

				for _, target := range ruleItem.Predicate.Targets {
					switch ruleItem.Predicate.Op {
					case Rx, Pmf, PmFromFile:
						_, ok := scanResults.GetRxResultsFor(rule.ID, curRuleItemIdx, target)
						if ok {
							matchFound = true
						}
					case Eq, Ge, Gt, Le, Lt:
						matchFound, _, _ = ruleItem.Predicate.eval(r.perRequestEnv)
					}
				}

				if matchFound {
					log.WithFields(log.Fields{"ruleID": rule.ID, "ruleItemIdx": curRuleItemIdx}).Trace("Match")

					for actionIdx := range ruleItem.Actions {
						ar := ruleItem.Actions[actionIdx].execute(r.perRequestEnv)

						if ar.err != nil {
							log.WithFields(log.Fields{"ruleID": rule.ID, "ruleItemIdx": curRuleItemIdx, "error": ar.err}).Trace("Error during action")
						}

						// Not letting action related events affect the WAF decision as of now.
						if ruleItem.Actions[actionIdx].isDisruptive() {
							return ar.allow, ar.statusCode, nil
						}
					}
				} else {
					isChainDone = true
				}
			}
		}
	}

	return true, 200, nil
}
