package secrule

import (
	"azwaf/waf"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
)

// RuleEvaluator processes the incoming request against all parsed rules
type RuleEvaluator interface {
	ProcessPhase(phase int) (decision waf.Decision)
	IsForceRequestBodyScanning() bool
}

// RuleEvaluatorTriggeredCb is will be called when the rule evaluator has decided that a rule is triggered.
type RuleEvaluatorTriggeredCb = func(stmt Statement, decision waf.Decision, msg string, logData string)

type ruleEvaluatorImpl struct {
	phase                    int
	logger                   zerolog.Logger
	perRequestEnv            *environment
	statements               []Statement
	scanResults              *ScanResults
	triggeredCb              RuleEvaluatorTriggeredCb
	cleanUpCapturedVars      func()
	skipAfter                string
	stmtID                   int
	shouldLog                bool
	msg                      Value
	logData                  Value
	decision                 waf.Decision
	forceRequestBodyScanning bool
}

func (re *ruleEvaluatorImpl) ProcessPhase(phase int) (decision waf.Decision) {
	re.phase = phase
	re.decision = waf.Pass
	re.cleanUpCapturedVars = nil
	re.skipAfter = ""

	defer func() {
		if re.cleanUpCapturedVars != nil {
			re.cleanUpCapturedVars()
		}
	}()

	for _, stmt := range re.statements {
		// If we are currently looking for a skipAfter marker, then keep skipping until we find it.
		if re.skipAfter != "" {
			if m, ok := stmt.(*Marker); ok {
				if m.Label == re.skipAfter {
					re.skipAfter = ""
				}
			}

			continue
		}

		// Are we in the right phase for this statement?
		if checkPhaseShouldContinue(re.phase, stmt) {
			continue
		}

		re.shouldLog = true
		re.stmtID = 0
		re.msg = nil
		re.logData = nil

		switch stmt := stmt.(type) {
		case *Rule:
			re.stmtID = stmt.ID

			re.perRequestEnv.resetMatchesCollections()

			for curRuleItemIdx, ruleItem := range stmt.Items {
				anyRuleItemTriggered := false
				for _, target := range ruleItem.Predicate.Targets {
					triggered, matches, err := evalPredicate(re.perRequestEnv, ruleItem, target, re.scanResults, stmt, curRuleItemIdx)
					if err != nil {
						re.logger.Warn().Int("ruleID", re.stmtID).Int("ruleItemIdx", curRuleItemIdx).Err(err).Msg("Error evaluating predicate")
					}

					if triggered {
						// Update the environment matched_var, matched_vars, etc., for any rule that may need it during late scanning.
						re.perRequestEnv.updateMatches(matches)

						var latestMatch Match
						if len(matches) > 0 {
							latestMatch = matches[len(matches)-1]
						}

						// Some actions are to be run after each rule item.
						re.runActions(ruleItem.Actions, latestMatch)

						// Some actions are only to be run when all rule items triggered.
						if curRuleItemIdx == len(stmt.Items)-1 {
							for _, r := range stmt.Items {
								re.runActionsAfterAllRuleItemsTriggered(r.Actions)
							}

							if phase == 5 && re.decision != waf.Pass {
								re.decision = waf.Pass
							}

							if re.shouldLog {
								re.triggeredCb(stmt, re.decision, re.msg.expandMacros(re.perRequestEnv).string(), re.logData.expandMacros(re.perRequestEnv).string())
							}

							if re.decision != waf.Pass {
								return re.decision
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
			re.stmtID = stmt.ID
			re.runActions(stmt.Actions, Match{})
			re.runActionsAfterAllRuleItemsTriggered(stmt.Actions)

			if phase == 5 && re.decision != waf.Pass {
				re.decision = waf.Pass
			}

			if re.shouldLog {
				re.triggeredCb(stmt, re.decision, re.msg.expandMacros(re.perRequestEnv).string(), re.logData.expandMacros(re.perRequestEnv).string())
			}

			if re.decision != waf.Pass {
				return re.decision
			}
		}

		if re.cleanUpCapturedVars != nil {
			re.cleanUpCapturedVars()
		}
	}

	return re.decision
}

func (re *ruleEvaluatorImpl) IsForceRequestBodyScanning() bool {
	return re.forceRequestBodyScanning
}

// This runs the actions that need to run after each rule item had a target that triggered
func (re *ruleEvaluatorImpl) runActions(actions []Action, match Match) {
	// TODO implement the "pass" action. If there are X many matches, the pass action is supposed to make all actions execute X many times.

	for _, action := range actions {
		switch action := action.(type) {

		case *SetVarAction:
			err := executeSetVarAction(action, re.perRequestEnv)
			if err != nil {
				re.logger.Warn().Int("ruleID", re.stmtID).Err(err).Msg("Error executing setVar action")
			}

		case *NoLogAction:
			re.shouldLog = false

		case *LogAction:
			re.shouldLog = true

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

				re.perRequestEnv.set("tx."+strconv.Itoa(i), Value{t})
			}

			re.cleanUpCapturedVars = func() {
				// Clean up tx.1, tx.2, etc., if they were set
				for i := 0; i < txVarCount; i++ {
					re.perRequestEnv.delete("tx." + strconv.Itoa(i))
				}
				re.cleanUpCapturedVars = nil
			}

		case *CtlAction:
			switch action.setting {
			case ForceRequestBodyVariable:
				if strings.EqualFold(action.value.expandMacros(re.perRequestEnv).string(), "on") {
					re.forceRequestBodyScanning = true
				}
			default:
				re.logger.Warn().Int("action.setting", int(action.setting)).Msg("Unsupported ctlAction")
			}
		}
	}
}

// This runs the actions that need to run after all rule items have triggered
func (re *ruleEvaluatorImpl) runActionsAfterAllRuleItemsTriggered(actions []Action) {
	re.logger.Debug().Int("ruleID", re.stmtID).Msg("Rule triggered")

	// Some actions are to be run after all rule items in the chain triggered.
	for _, action := range actions {
		switch action := action.(type) {

		case *SkipAfterAction:
			re.skipAfter = action.Label
			re.logger.Debug().Str("label", re.skipAfter).Msg("Skipping to marker")

		case *MsgAction:
			re.msg = action.Msg

		case *LogDataAction:
			re.logData = action.LogData

		case *AllowAction:
			re.decision = waf.Allow

		case *DenyAction:
			re.decision = waf.Block

		case *CtlAction:

		}
	}
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

func evalPredicate(env *environment, ruleItem RuleItem, target Target, scanResults *ScanResults, rule *Rule, curRuleItemIdx int) (triggered bool, matches []Match, err error) {
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

func evalPredicateLateScan(env *environment, ruleItem RuleItem, target Target, scanResults *ScanResults, rule *Rule, curRuleItemIdx int) (result bool, match Match, err error) {
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
