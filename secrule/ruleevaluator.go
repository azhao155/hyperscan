package secrule

import (
	"azwaf/waf"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
)

// RuleEvaluator processes the incoming request against all parsed rules
type RuleEvaluator interface {
	Process(logger zerolog.Logger, perRequestEnv environment, statements []Statement, scanResults *ScanResults, triggeredCb RuleEvaluatorTriggeredCb) (decision waf.Decision, statusCode int, err error)
}

// RuleEvaluatorTriggeredCb is will be called when the rule evaluator has decided that a rule is triggered.
type RuleEvaluatorTriggeredCb = func(stmt Statement, isDisruptive bool, msg string, logData string)

type ruleEvaluatorImpl struct{}

// NewRuleEvaluator creates a new rule evaluator
func NewRuleEvaluator() RuleEvaluator {
	return &ruleEvaluatorImpl{}
}

func (r *ruleEvaluatorImpl) Process(logger zerolog.Logger, perRequestEnv environment, statements []Statement, scanResults *ScanResults, triggeredCb RuleEvaluatorTriggeredCb) (decision waf.Decision, statusCode int, err error) {
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

func (r *ruleEvaluatorImpl) processPhase(logger zerolog.Logger, phase int, perRequestEnv environment, statements []Statement, scanResults *ScanResults, triggeredCb RuleEvaluatorTriggeredCb) (decision waf.Decision, statusCode int, phaseDisruptive bool) {
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
						var t Token = StringToken(match.CaptureGroups[i])
						if n, err := strconv.Atoi(string(match.CaptureGroups[i])); err == nil {
							t = IntToken(n)
						}

						perRequestEnv.set("tx."+strconv.Itoa(i), Value{t})
					}

					cleanUpCapturedVars = func() {
						// Clean up tx.1, tx.2, etc., if they were set
						for i := 0; i < txVarCount; i++ {
							perRequestEnv.delete("tx." + strconv.Itoa(i))
						}
						cleanUpCapturedVars = nil
					}

				case *CtlAction:
					perRequestEnv.set(action.setting, action.value.expandMacros(perRequestEnv))
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

			perRequestEnv.resetMatchesCollections()

			for curRuleItemIdx, ruleItem := range stmt.Items {
				anyRuleItemTriggered := false
				for _, target := range ruleItem.Predicate.Targets {
					triggered, matches, err := evalPredicate(perRequestEnv, ruleItem, target, scanResults, stmt, curRuleItemIdx)
					if err != nil {
						logger.Warn().Int("ruleID", stmtID).Int("ruleItemIdx", curRuleItemIdx).Err(err).Msg("Error evaluating predicate")
					}

					if triggered {
						// Update the environment matched_var, matched_vars, etc., for any rule that may need it during late scanning.
						perRequestEnv.updateMatches(matches)

						var latestMatch Match
						if len(matches) > 0 {
							latestMatch = matches[len(matches)-1]
						}

						// Some actions are to be run after each rule item.
						runActions(ruleItem.Actions, latestMatch)

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

func evalPredicate(env environment, ruleItem RuleItem, target Target, scanResults *ScanResults, rule *Rule, curRuleItemIdx int) (triggered bool, matches []Match, err error) {
	if requiresLateScan(ruleItem.Predicate, target) {
		// We need to a late scan for this predicate now, because we were not able to do it in the scanning phase.
		// This is the less common case.
		triggered, match, err := evalPredicateLateScan(env, ruleItem, target, scanResults, rule, curRuleItemIdx)
		if err != nil {
			return false, nil, err
		}
		return triggered, []Match{match}, err
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
	matches = m

	return

}

func evalPredicateLateScan(env environment, ruleItem RuleItem, target Target, scanResults *ScanResults, rule *Rule, curRuleItemIdx int) (result bool, match Match, err error) {
	// A predicate that requires late scanning means that it could not be scanned in the request scanning phase, and therefore must be scanned now.
	// This is because either left or right side was a variable we could not yet know the value of in the request scanning phase.

	returnValIfTrigger := !ruleItem.Predicate.Neg

	isTxTarget := target.Name == TargetTx
	// TODO support regex selectors for tx variable names
	isTxTargetPresent := isTxTarget && env.hasKey(strings.ToLower(TargetNamesStrings[target.Name]+"."+target.Selector))

	if isTxTarget && !isTxTargetPresent && !target.IsCount {
		// This is a tx variable that is not set
		result = false
		return
	}

	var triggered bool
	triggered, match, err = ruleItem.Predicate.eval(target, scanResults, env)
	if triggered {
		result = returnValIfTrigger
		return
	}

	result = !returnValIfTrigger
	return
}

// We require a late scan (a scan in the eval phase as opposed to the req scan phase) if either left or right side was not known in the scan phase.
func requiresLateScan(predicate RulePredicate, target Target) bool {
	switch target.Name {
	case TargetMatchedVar, TargetMatchedVars, TargetMatchedVarName, TargetMatchedVarsNames, TargetTx:
		return true
	}

	if target.IsCount {
		return true
	}

	if predicate.Val.hasMacros() {
		return true
	}

	return false
}
