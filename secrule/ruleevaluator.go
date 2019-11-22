package secrule

import (
	"azwaf/waf"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
)

// RuleEvaluator processes the incoming request against all parsed rules
type RuleEvaluator interface {
	Process(logger zerolog.Logger, perRequestEnv envMap, statements []Statement, scanResults *ScanResults, triggeredCb RuleEvaluatorTriggeredCb) (decision waf.Decision, statusCode int, err error)
}

// RuleEvaluatorTriggeredCb is will be called when the rule evaluator has decided that a rule is triggered.
type RuleEvaluatorTriggeredCb = func(stmt Statement, isDisruptive bool, msg string, logData string)

type ruleEvaluatorImpl struct{}

// NewRuleEvaluator creates a new rule evaluator
func NewRuleEvaluator() RuleEvaluator {
	return &ruleEvaluatorImpl{}
}

func (r *ruleEvaluatorImpl) Process(logger zerolog.Logger, perRequestEnv envMap, statements []Statement, scanResults *ScanResults, triggeredCb RuleEvaluatorTriggeredCb) (decision waf.Decision, statusCode int, err error) {
	// Evaluate each phase, but stop if there was a disruptive action.
	for phase := 1; phase <= 4; phase++ {
		logger.Debug().Int("phase", phase).Msg("Starting rule evaluation phase")
		var phaseDisruptive = false
		decision, statusCode, phaseDisruptive = r.processPhase(logger, phase, perRequestEnv, statements, scanResults, triggeredCb)
		if phaseDisruptive {
			break
		}
	}

	// Phase 5 is special, because it cannot perform any disruptive actions.
	logger.Debug().Int("phase", 5).Msg("Starting rule evaluation phase")
	r.processPhase(logger, 5, perRequestEnv, statements, scanResults, triggeredCb)

	return
}

func (r *ruleEvaluatorImpl) processPhase(logger zerolog.Logger, phase int, perRequestEnv envMap, statements []Statement, scanResults *ScanResults, triggeredCb RuleEvaluatorTriggeredCb) (decision waf.Decision, statusCode int, phaseDisruptive bool) {
	var skipAfter string

	var cleanUpCapturedVars func()
	defer func() {
		if cleanUpCapturedVars != nil {
			cleanUpCapturedVars()
		}
	}()

	decision = waf.Pass
	statusCode = 200
	phaseDisruptive = false
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

		var stmtID int
		shouldLog := true
		var msg, logData Value

		// This runs the actions that need to run after each rule item had a target that triggered
		runActions := func(actions []Action, match Match) {
			// TODO implement the "pass" action. If there are X many matches, the pass action is supposed to make all actions execute X many times.

			for _, action := range actions {
				switch action := action.(type) {

				case *SetVarAction:
					err := executeSetVarAction(action, perRequestEnv)
					if err != nil {
						logger.Warn().Int("ruleID", stmtID).Err(err).Msg("Error executing setVar action")
					}

				case *NoLogAction:
					shouldLog = false

				case *LogAction:
					shouldLog = true

				case *CaptureAction:
					txVarCount := len(match.CaptureGroups)
					if txVarCount > 10 {
						txVarCount = 10
					}

					for i := 0; i < txVarCount; i++ {
						perRequestEnv.set("tx."+strconv.Itoa(i), &stringObject{Value: string(match.CaptureGroups[i])})
					}

					cleanUpCapturedVars = func() {
						// Clean up tx.1, tx.2, etc., if they were set
						for i := 0; i < txVarCount; i++ {
							perRequestEnv.delete("tx." + strconv.Itoa(i))
						}
						cleanUpCapturedVars = nil
					}

				case *CtlAction:
					perRequestEnv.set(action.setting, &stringObject{Value: action.value})
				}
			}
		}

		// This runs the actions that need to run after all rule items have triggered
		runActionsAfterAllRuleItemsTriggered := func(actions []Action) {
			logger.Debug().Int("ruleID", stmtID).Msg("Rule triggered")

			// Some actions are to be run after all rule items in the chain triggered.
			for _, action := range actions {
				switch action := action.(type) {

				case *SkipAfterAction:
					skipAfter = action.Label
					logger.Debug().Str("label", skipAfter).Msg("Skipping to marker")

				case *MsgAction:
					msg = action.Msg

				case *LogDataAction:
					logData = action.LogData

				case *AllowAction:
					phaseDisruptive = true
					decision = waf.Allow

				case *DenyAction:
					phaseDisruptive = true
					decision = waf.Block
					statusCode = 403

				}
			}
		}

		switch stmt := stmt.(type) {
		case *Rule:
			stmtID = stmt.ID

			for curRuleItemIdx, ruleItem := range stmt.Items {
				anyRuleItemTriggered := false
				for _, target := range ruleItem.Predicate.Targets {
					triggered, match := evalPredicate(perRequestEnv, ruleItem, target, scanResults, stmt, curRuleItemIdx)
					if triggered {
						perRequestEnv.matchedVar = match.EntireFieldContent
						perRequestEnv.matchedVarName = match.TargetName

						// If there is a field name too, then append it to matchedVarName.
						if len(match.FieldName) > 0 {
							perRequestEnv.matchedVarName = make([]byte, 0, len(match.TargetName)+1+len(match.FieldName))
							perRequestEnv.matchedVarName = append(perRequestEnv.matchedVarName, match.TargetName...)
							perRequestEnv.matchedVarName = append(perRequestEnv.matchedVarName, ':')
							perRequestEnv.matchedVarName = append(perRequestEnv.matchedVarName, match.FieldName...)
						}

						// Some actions are to be run after each rule item.
						runActions(ruleItem.Actions, match)

						// Some actions are only to be run when all rule items triggered.
						if curRuleItemIdx == len(stmt.Items)-1 {
							for _, r := range stmt.Items {
								runActionsAfterAllRuleItemsTriggered(r.Actions)
							}

							if shouldLog {
								triggeredCb(stmt, phaseDisruptive, msg.expandMacros(perRequestEnv).string(), logData.expandMacros(perRequestEnv).string())
							}

							if phaseDisruptive {
								return
							}
						}

						anyRuleItemTriggered = true
					}
				}

				if !anyRuleItemTriggered {
					break
				}
			}

		case *ActionStmt:
			stmtID = stmt.ID
			runActions(stmt.Actions, Match{})
			runActionsAfterAllRuleItemsTriggered(stmt.Actions)

			if shouldLog {
				triggeredCb(stmt, phaseDisruptive, msg.expandMacros(perRequestEnv).string(), logData.expandMacros(perRequestEnv).string())
			}

			if phaseDisruptive {
				return
			}
		}

		if cleanUpCapturedVars != nil {
			cleanUpCapturedVars()
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

func evalPredicate(env envMap, ruleItem RuleItem, target Target, scanResults *ScanResults, rule *Rule, curRuleItemIdx int) (triggered bool, match Match) {
	if requiresLateScan(ruleItem.Predicate, target) {
		// We need to a late scan for this predicate now, because we were not able to do it in the scanning phase.
		// This is the less common case.
		triggered = evalPredicateLateScan(env, ruleItem, target, scanResults, rule, curRuleItemIdx)
		return
	}

	// If we do not require a late scan, it's because we know the answer to this predicate already.
	// The scanning for this predicate was done in the request scanning phase.
	// This is the simplest and most common case.

	if scanResults.targetsCount[target] == 0 {
		// This a target we never even came across
		triggered = false
		return
	}

	returnValIfTrigger := !ruleItem.Predicate.Neg
	m, ok := scanResults.GetResultsFor(rule.ID, curRuleItemIdx, target)
	if !ok {
		triggered = !returnValIfTrigger
		return
	}

	triggered = returnValIfTrigger
	match = m

	return

}

func evalPredicateLateScan(env envMap, ruleItem RuleItem, target Target, scanResults *ScanResults, rule *Rule, curRuleItemIdx int) bool {
	// A predicate that requires late scanning means that it could not be scanned in the request scanning phase, and therefore must be scanned now.
	// This is because either left or right side was a variable we could not yet know the value of in the request scanning phase.

	returnValIfTrigger := !ruleItem.Predicate.Neg

	isTxTarget := strings.EqualFold(target.Name, "tx")
	isTxTargetPresent := isTxTarget && env.hasKey(target.Name+"."+target.Selector) // TODO support regex selectors for tx variable names

	if isTxTarget && !isTxTargetPresent && !target.IsCount {
		// This is a tx variable that is not set
		return false
	}

	triggered, _, _ := ruleItem.Predicate.eval(target, scanResults, env)
	if triggered {
		return returnValIfTrigger
	}
	return !returnValIfTrigger
}

// We require a late scan (a scan in the eval phase as opposed to the req scan phase) if either left or right side is a variable.
func requiresLateScan(predicate RulePredicate, target Target) bool {
	if strings.EqualFold(target.Name, "tx") {
		return true
	}

	if len(predicate.valMacroMatches) > 0 {
		return true
	}

	if target.IsCount {
		return true
	}

	return false
}
