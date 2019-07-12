package secrule

import (
	log "github.com/sirupsen/logrus"
)

// RuleEvaluator processes the incoming request against all parsed rules
type RuleEvaluator interface {
	Process(statements []Statement, scanResults *ScanResults, triggeredCb RuleEvaluatorTriggeredCb) (allow bool, statusCode int, err error)
}

// RuleEvaluatorTriggeredCb is will be called when the rule evaluator has decided that a rule is triggered.
type RuleEvaluatorTriggeredCb = func(stmt Statement, isDisruptive bool, logMsg string)

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

func (r *ruleEvaluatorImpl) Process(statements []Statement, scanResults *ScanResults, triggeredCb RuleEvaluatorTriggeredCb) (allow bool, statusCode int, err error) {
	// The triggered callback is optional. Default to do nothing.
	if triggeredCb == nil {
		triggeredCb = func(stmt Statement, isDisruptive bool, logMsg string) {}
	}

	for _, stmt := range statements {
		switch stmt := stmt.(type) {
		case *Rule:
			rule := stmt
			allChainItemsMatched := true
			for curRuleItemIdx, ruleItem := range rule.Items {
				log.WithFields(log.Fields{"ruleID": rule.ID, "ruleItemIdx": curRuleItemIdx}).Trace("Evaluating SecRule")

				if !evalPredicate(r.perRequestEnv, ruleItem, scanResults, rule, curRuleItemIdx) {
					allChainItemsMatched = false
					break
				}
			}

			if allChainItemsMatched {
				log.WithFields(log.Fields{"ruleID": rule.ID}).Trace("SecRule triggered")

				anyDisruptive := false
				var logMsg string

				for _, ruleItem := range rule.Items {
					// TODO implement the "pass" action. If there are X many matches, the pass action is supposed to make all actions execute X many times.

					disruptive, actionAllow, actionStatusCode, actionLogMsg := r.runActions(ruleItem.Actions, rule.ID)

					if disruptive {
						anyDisruptive = true
						allow = actionAllow
						statusCode = actionStatusCode
					}

					if actionLogMsg != "" {
						logMsg = actionLogMsg
					}
				}

				if !stmt.Nolog {
					// TODO triggeredCb should get match data (which target and string was matched) from the LAST item of the chain, even if the disruptive action is in the first.
					triggeredCb(stmt, anyDisruptive, logMsg)
				}

				if anyDisruptive {
					return
				}
			}

		case *ActionStmt:
			actionStmt := stmt

			log.WithFields(log.Fields{"ruleID": actionStmt.ID}).Trace("Evaluating SecAction")

			disruptive, actionAllow, actionStatusCode, logMsg := r.runActions(actionStmt.Actions, actionStmt.ID)

			if !stmt.Nolog {
				triggeredCb(stmt, disruptive, logMsg)
			}

			if disruptive {
				allow = actionAllow
				statusCode = actionStatusCode
				return
			}
		}
	}

	allow = true
	statusCode = 200
	return
}

func evalPredicate(env envMap, ruleItem RuleItem, scanResults *ScanResults, rule *Rule, curRuleItemIdx int) bool {
	for _, target := range ruleItem.Predicate.Targets {
		switch ruleItem.Predicate.Op {
		case Rx, Pm, Pmf, PmFromFile, BeginsWith, EndsWith, Contains, ContainsWord, Strmatch, Streq, Within:
			_, ok := scanResults.GetRxResultsFor(rule.ID, curRuleItemIdx, target)
			if ok {
				return true
			}

			if len(ruleItem.Predicate.valMacroMatches) > 0 {
				matchFound, _, _ := ruleItem.Predicate.eval(env)
				if matchFound {
					return true
				}
			}
		case Eq, Ge, Gt, Le, Lt:
			matchFound, _, _ := ruleItem.Predicate.eval(env)
			if matchFound {
				return true
			}
		}
	}

	return false
}

func (r *ruleEvaluatorImpl) runActions(actions []actionHandler, ruleID int) (disruptive bool, allow bool, statusCode int, logMsg string) {
	// TODO implement the "log" action, so we can put something in logMsg

	for _, action := range actions {
		ar := action.execute(r.perRequestEnv)

		if ar.err != nil {
			log.WithFields(log.Fields{"ruleID": ruleID, "error": ar.err}).Warn("Error executing action")
		}

		// Not letting action related errors affect the WAF decision as of now.
		// TODO decide whether action errors should block the req
		if action.isDisruptive() {
			disruptive = true
			allow = ar.allow
			statusCode = ar.statusCode
			return
		}
	}

	return
}
