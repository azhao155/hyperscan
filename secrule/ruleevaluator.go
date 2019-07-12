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
			isChainDone := false
			for curRuleItemIdx, ruleItem := range rule.Items {
				if isChainDone {
					break
				}

				log.WithFields(log.Fields{"ruleID": rule.ID, "ruleItemIdx": curRuleItemIdx}).Trace("Evaluating SecRule")

				matchFound := false

				for _, target := range ruleItem.Predicate.Targets {
					switch ruleItem.Predicate.Op {
					case Rx, Pm, Pmf, PmFromFile, BeginsWith, EndsWith, Contains, ContainsWord, Strmatch, Streq, Within:
						_, ok := scanResults.GetRxResultsFor(rule.ID, curRuleItemIdx, target)
						if ok {
							matchFound = true
						}

						if len(ruleItem.Predicate.valMacroMatches) > 0 {
							matchFound, _, _ = ruleItem.Predicate.eval(r.perRequestEnv)
						}
					case Eq, Ge, Gt, Le, Lt:
						matchFound, _, _ = ruleItem.Predicate.eval(r.perRequestEnv)
					}
				}

				if matchFound {
					log.WithFields(log.Fields{"ruleID": rule.ID, "ruleItemIdx": curRuleItemIdx}).Trace("SecRule chain item triggered")
					disruptive, actionAllow, actionStatusCode, logMsg := r.runActions(ruleItem.Actions, rule.ID)
					if disruptive {
						allow = actionAllow
						statusCode = actionStatusCode
						triggeredCb(stmt, true, logMsg)
						return
					}

					triggeredCb(stmt, false, logMsg)
				} else {
					isChainDone = true
				}
			}

		case *ActionStmt:
			actionStmt := stmt

			log.WithFields(log.Fields{"ruleID": actionStmt.ID}).Trace("Evaluating SecAction")

			disruptive, actionAllow, actionStatusCode, logMsg := r.runActions(actionStmt.Actions, actionStmt.ID)
			if disruptive {
				allow = actionAllow
				statusCode = actionStatusCode
				triggeredCb(stmt, true, logMsg)
				return
			}

			triggeredCb(stmt, false, logMsg)
		}
	}

	return true, 200, nil
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
