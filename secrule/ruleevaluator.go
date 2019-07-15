package secrule

import (
	log "github.com/sirupsen/logrus"
)

// RuleEvaluator processes the incoming request against all parsed rules
type RuleEvaluator interface {
	Process(perRequestEnv envMap, statements []Statement, scanResults *ScanResults, triggeredCb RuleEvaluatorTriggeredCb) (allow bool, statusCode int, err error)
}

// RuleEvaluatorTriggeredCb is will be called when the rule evaluator has decided that a rule is triggered.
type RuleEvaluatorTriggeredCb = func(stmt Statement, isDisruptive bool, msg string, logData string)

type ruleEvaluatorImpl struct{}

// NewRuleEvaluator creates a new rule evaluator
func NewRuleEvaluator() RuleEvaluator {
	return &ruleEvaluatorImpl{}
}

func (r *ruleEvaluatorImpl) Process(perRequestEnv envMap, statements []Statement, scanResults *ScanResults, triggeredCb RuleEvaluatorTriggeredCb) (allow bool, statusCode int, err error) {
	// The triggered callback is optional. Default to do nothing.
	if triggeredCb == nil {
		triggeredCb = func(stmt Statement, isDisruptive bool, msg string, logData string) {}
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

		// Are we in the right phase for this statement?
		if checkPhaseShouldContinue(phase, stmt) {
			continue
		}

		var actions []Action
		var stmtID int
		var triggered bool

		switch stmt := stmt.(type) {
		case *Rule:
			triggered = true
			for curRuleItemIdx, ruleItem := range stmt.Items {
				log.WithFields(log.Fields{"ruleID": stmt.ID, "ruleItemIdx": curRuleItemIdx}).Trace("Evaluating SecRule")

				if !evalPredicate(perRequestEnv, ruleItem, scanResults, stmt, curRuleItemIdx) {
					triggered = false
					break
				}
			}

			// Did all chain items match?
			if triggered {
				log.WithFields(log.Fields{"ruleID": stmt.ID}).Trace("SecRule triggered")

				stmtID = stmt.ID

				// Queue up all actions to be run
				for _, ruleItem := range stmt.Items {
					actions = append(actions, ruleItem.Actions...)
				}
			}

		case *ActionStmt:
			log.WithFields(log.Fields{"ruleID": stmt.ID}).Trace("SecAction triggered")
			triggered = true
			stmtID = stmt.ID
			actions = append(actions, stmt.Actions...)
		}

		shouldLog := true
		var msg string
		if len(actions) > 0 {
			// TODO implement the "pass" action. If there are X many matches, the pass action is supposed to make all actions execute X many times.

			for _, action := range actions {
				switch action := action.(type) {

				case *SkipAfterAction:
					log.WithFields(log.Fields{"label": skipAfter}).Trace("Skipping to marker")
					skipAfter = action.Label

				case *SetVarAction:
					err := executeSetVarAction(action, perRequestEnv)
					if err != nil {
						log.WithFields(log.Fields{"ruleID": stmtID, "error": err}).Warn("Error executing setVar action")
					}

				case *NoLogAction:
					shouldLog = false

				case *LogAction:
					shouldLog = true

				case *MsgAction:
					msg = action.Msg

				case *DenyAction:
					phaseDisruptive = true
					allow = false
					statusCode = 403

				}
			}
		}

		if triggered {
			if shouldLog {
				// TODO implement the "logdata" action, so we can put something better than "" in logData
				triggeredCb(stmt, phaseDisruptive, msg, "")
			}

			if phaseDisruptive {
				return
			}
		}
	}

	return
}

func checkPhaseShouldContinue(phase int, stmt Statement) bool {
	var stmtPhase int
	switch stmt := stmt.(type) {
	case *Rule:
		stmtPhase = stmt.Phase
	case *ActionStmt:
		stmtPhase = stmt.Phase
	}
	if stmtPhase == 0 {
		stmtPhase = 2 // Phase 2 is the default phase
	}
	if stmtPhase != phase {
		// TODO potential small optimization: pre-arrange statements into phases before passing them to processPhase
		return true
	}

	return false
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

func (r *ruleEvaluatorImpl) runActions(perRequestEnv envMap, actions []Action, ruleID int) (disruptive bool, allow bool, statusCode int, logMsg string, skipAfter string) {

	return
}
