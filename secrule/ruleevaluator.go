package secrule

import (
	log "github.com/sirupsen/logrus"
)

// RuleEvaluator processes the incoming request against all parsed rules
type RuleEvaluator interface {
	Process(perRequestEnv envMap, statements []Statement, scanResults *ScanResults, triggeredCb RuleEvaluatorTriggeredCb) (allow bool, statusCode int, err error)
}

// RuleEvaluatorTriggeredCb is will be called when the rule evaluator has decided that a rule is triggered.
type RuleEvaluatorTriggeredCb = func(stmt Statement, isDisruptive bool, logMsg string)

type ruleEvaluatorImpl struct{}

// NewRuleEvaluator creates a new rule evaluator
func NewRuleEvaluator() RuleEvaluator {
	return &ruleEvaluatorImpl{}
}

func (r *ruleEvaluatorImpl) Process(perRequestEnv envMap, statements []Statement, scanResults *ScanResults, triggeredCb RuleEvaluatorTriggeredCb) (allow bool, statusCode int, err error) {
	// The triggered callback is optional. Default to do nothing.
	if triggeredCb == nil {
		triggeredCb = func(stmt Statement, isDisruptive bool, logMsg string) {}
	}

	// Evaluate each phase, but stop if there was a disruptive action.
	anyDisruptive := false
	for phase := 1; phase <= 4; phase++ {
		log.Debugf("Starting rule evaluation phase %v", phase)
		phaseAllow, phaseStatusCode, phaseDisruptive := r.processPhase(phase, perRequestEnv, statements, scanResults, triggeredCb)
		if phaseDisruptive {
			allow = phaseAllow
			statusCode = phaseStatusCode
			anyDisruptive = true
			break
		}
	}

	// Phase 5 is special, because it cannot perform any disruptive actions.
	log.Debug("Starting rule evaluation phase 5")
	r.processPhase(5, perRequestEnv, statements, scanResults, triggeredCb)

	if !anyDisruptive {
		allow = true
		statusCode = 200
	}

	return
}

func (r *ruleEvaluatorImpl) processPhase(phase int, perRequestEnv envMap, statements []Statement, scanResults *ScanResults, triggeredCb RuleEvaluatorTriggeredCb) (allow bool, statusCode int, phaseDisruptive bool) {
	var skipAfter string

	for _, stmt := range statements {
		// If we are currently looking for a skipAfter marker, then keep skipping until we find it.
		if skipAfter != "" {
			if m, ok := stmt.(*Marker); ok {
				if m.Label == skipAfter {
					skipAfter = ""
				}
			}

			continue
		}

		switch stmt := stmt.(type) {
		case *Rule:
			rule := stmt

			// Are we in the right phase for this rule?
			p := rule.Phase
			if p == 0 {
				p = 2 // Phase 2 is the default phase for SecRules
			}
			if p != phase {
				// TODO potential small optimization: pre-arrange statements into phases before passing them to processPhase
				continue
			}

			allChainItemsMatched := true
			for curRuleItemIdx, ruleItem := range rule.Items {
				log.WithFields(log.Fields{"ruleID": rule.ID, "ruleItemIdx": curRuleItemIdx}).Trace("Evaluating SecRule")

				if !evalPredicate(perRequestEnv, ruleItem, scanResults, rule, curRuleItemIdx) {
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

					disruptive, actionAllow, actionStatusCode, actionLogMsg, actionSkipAfter := r.runActions(perRequestEnv, ruleItem.Actions, rule.ID)

					if disruptive {
						anyDisruptive = true
						allow = actionAllow
						statusCode = actionStatusCode
					}

					if actionLogMsg != "" {
						logMsg = actionLogMsg
					}

					if actionSkipAfter != "" {
						log.WithFields(log.Fields{"label": skipAfter}).Trace("Skipping to marker")

						skipAfter = actionSkipAfter
					}
				}

				if !stmt.Nolog {
					// TODO triggeredCb should get match data (which target and string was matched) from the LAST item of the chain, even if the disruptive action is in the first.
					triggeredCb(stmt, anyDisruptive, logMsg)
				}

				if anyDisruptive {
					phaseDisruptive = true
					return
				}
			}

		case *ActionStmt:
			actionStmt := stmt

			// Are we in the right phase for this action statement?
			p := actionStmt.Phase
			if p == 0 {
				p = 2 // Phase 2 is the default phase for SecActions
			}
			if p != phase {
				continue
			}

			log.WithFields(log.Fields{"ruleID": actionStmt.ID}).Trace("Evaluating SecAction")

			disruptive, actionAllow, actionStatusCode, logMsg, actionSkipAfter := r.runActions(perRequestEnv, actionStmt.Actions, actionStmt.ID)

			if !stmt.Nolog {
				triggeredCb(stmt, disruptive, logMsg)
			}

			if disruptive {
				allow = actionAllow
				statusCode = actionStatusCode
				phaseDisruptive = true
				return
			}

			if actionSkipAfter != "" {
				log.WithFields(log.Fields{"label": skipAfter}).Trace("Skipping to marker")

				skipAfter = actionSkipAfter
			}
		}
	}

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

func (r *ruleEvaluatorImpl) runActions(perRequestEnv envMap, actions []actionHandler, ruleID int) (disruptive bool, allow bool, statusCode int, logMsg string, skipAfter string) {
	// TODO implement the "log" action, so we can put something in logMsg

	for _, action := range actions {
		switch action := action.(type) {
		case *skipAfterAction:
			skipAfter = action.label
		}

		ar := action.execute(perRequestEnv)

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
