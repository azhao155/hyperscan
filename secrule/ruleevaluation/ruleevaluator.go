package ruleevaluation

import (
	sr "azwaf/secrule"
	ast "azwaf/secrule/ast"

	"azwaf/waf"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
)

type ruleEvaluatorImpl struct {
	phase                    int
	logger                   zerolog.Logger
	perRequestEnv            sr.Environment
	statements               []ast.Statement
	scanResults              *sr.ScanResults
	triggeredCb              sr.RuleEvaluatorTriggeredCb
	cleanUpCapturedVars      func()
	skipAfter                string
	stmtID                   int
	shouldLog                bool
	msg                      ast.Value
	logData                  ast.Value
	decision                 waf.Decision
	forceRequestBodyScanning bool
}

const defaultPhase = 2

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
			if m, ok := stmt.(*ast.Marker); ok {
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
		case *ast.Rule:
			re.stmtID = stmt.ID

			re.perRequestEnv.ResetMatchesCollections()

			for curRuleItemIdx, ruleItem := range stmt.Items {
				anyRuleItemTriggered := false
				for _, target := range ruleItem.Predicate.Targets {
					triggered, matches, err := evalPredicate(re.perRequestEnv, ruleItem, target, re.scanResults, stmt, curRuleItemIdx)
					if err != nil {
						re.logger.Warn().Int("ruleID", re.stmtID).Int("ruleItemIdx", curRuleItemIdx).Err(err).Msg("Error evaluating predicate")
					}

					if triggered {
						// Update the environment matched_var, matched_vars, etc., for any rule that may need it during late scanning.
						re.perRequestEnv.UpdateMatches(matches)

						if len(matches) == 0 {
							// This could happen on a rule that did all its scanning in the scan phase, and had a negation. Hopefully the match value is never needed in this case...
							matches = []sr.Match{sr.Match{}}
						}

						// Some actions are to be run after each rule item for each match.
						for _, m := range matches {
							re.runActions(ruleItem.Actions, m)
						}

						// Some actions are only to be run when all rule items triggered.
						if curRuleItemIdx == len(stmt.Items)-1 {
							for _, r := range stmt.Items {
								re.runActionsAfterAllRuleItemsTriggered(r.Actions)
							}

							if phase == 5 && re.decision != waf.Pass {
								re.decision = waf.Pass
							}

							if re.shouldLog {
								re.triggeredCb(stmt, re.decision, re.perRequestEnv.ExpandMacros(re.msg).String(), re.perRequestEnv.ExpandMacros(re.logData).String())
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

		case *ast.ActionStmt:
			re.stmtID = stmt.ID
			re.runActions(stmt.Actions, sr.Match{})
			re.runActionsAfterAllRuleItemsTriggered(stmt.Actions)

			if phase == 5 && re.decision != waf.Pass {
				re.decision = waf.Pass
			}

			if re.shouldLog {
				re.triggeredCb(stmt, re.decision, re.perRequestEnv.ExpandMacros(re.msg).String(), re.perRequestEnv.ExpandMacros(re.logData).String())
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
func (re *ruleEvaluatorImpl) runActions(actions []ast.Action, match sr.Match) {
	// TODO implement the "pass" action. If there are X many matches, the pass action is supposed to make all actions execute X many times.

	for _, action := range actions {
		switch action := action.(type) {

		case *ast.SetVarAction:
			err := executeSetVarAction(action, re.perRequestEnv)
			if err != nil {
				re.logger.Warn().Int("ruleID", re.stmtID).Err(err).Msg("Error executing setVar action")
			}

		case *ast.NoLogAction:
			re.shouldLog = false

		case *ast.LogAction:
			re.shouldLog = true

		case *ast.CaptureAction:
			txVarCount := len(match.CaptureGroups)
			if txVarCount > 10 {
				txVarCount = 10
			}

			for i := 0; i < txVarCount; i++ {
				var t ast.Token = ast.StringToken(match.CaptureGroups[i])
				if n, err := strconv.Atoi(string(match.CaptureGroups[i])); err == nil {
					t = ast.IntToken(n)
				}

				re.perRequestEnv.Set(ast.EnvVarTx, strconv.Itoa(i), ast.Value{t})
			}

			re.cleanUpCapturedVars = func() {
				// Clean up tx.1, tx.2, etc., if they were set
				for i := 0; i < txVarCount; i++ {
					re.perRequestEnv.Delete(ast.EnvVarTx, strconv.Itoa(i))
				}
				re.cleanUpCapturedVars = nil
			}

		case *ast.CtlAction:
			switch action.Setting {
			case ast.ForceRequestBodyVariable:
				if strings.EqualFold(re.perRequestEnv.ExpandMacros(action.Value).String(), "on") {
					re.forceRequestBodyScanning = true
				}
			default:
				re.logger.Warn().Int("action.setting", int(action.Setting)).Msg("Unsupported ctlAction")
			}
		}
	}
}

// This runs the actions that need to run after all rule items have triggered
func (re *ruleEvaluatorImpl) runActionsAfterAllRuleItemsTriggered(actions []ast.Action) {
	re.logger.Debug().Int("ruleID", re.stmtID).Msg("Rule triggered")

	// Some actions are to be run after all rule items in the chain triggered.
	for _, action := range actions {
		switch action := action.(type) {

		case *ast.SkipAfterAction:
			re.skipAfter = action.Label
			re.logger.Debug().Str("label", re.skipAfter).Msg("Skipping to marker")

		case *ast.MsgAction:
			re.msg = action.Msg

		case *ast.LogDataAction:
			re.logData = action.LogData

		case *ast.AllowAction:
			re.decision = waf.Allow

		case *ast.DenyAction:
			re.decision = waf.Block

		case *ast.CtlAction:

		}
	}
}

func checkPhaseShouldContinue(phase int, stmt ast.Statement) bool {
	var stmtPhase int
	switch stmt := stmt.(type) {
	case *ast.Rule:
		stmtPhase = stmt.Phase
	case *ast.ActionStmt:
		stmtPhase = stmt.Phase
	}
	if stmtPhase == 0 {
		stmtPhase = defaultPhase
	}
	if stmtPhase != phase {
		// TODO potential small optimization: pre-arrange statements into phases before passing them to processPhase
		return true
	}

	return false
}

func evalPredicate(env sr.Environment, ruleItem ast.RuleItem, target ast.Target, scanResults *sr.ScanResults, rule *ast.Rule, curRuleItemIdx int) (triggered bool, matches []sr.Match, err error) {
	if requiresLateScan(ruleItem.Predicate, target) {
		// We need to a late scan for this predicate now, because we were not able to do it in the scanning phase.
		// This is the less common case.
		triggered, match, err := evalPredicateLateScan(env, ruleItem, target, scanResults, rule, curRuleItemIdx)
		if err != nil {
			return false, nil, err
		}
		return triggered, []sr.Match{match}, err
	}

	// If we do not require a late scan, it's because we know the answer to this predicate already.
	// The scanning for this predicate was done in the request scanning phase.
	// This is the simplest and most common case.

	if scanResults.TargetsCount[target] == 0 {
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

func evalPredicateLateScan(env sr.Environment, ruleItem ast.RuleItem, target ast.Target, scanResults *sr.ScanResults, rule *ast.Rule, curRuleItemIdx int) (result bool, match sr.Match, err error) {
	// A predicate that requires late scanning means that it could not be scanned in the request scanning phase, and therefore must be scanned now.
	// This is because either left or right side was a variable we could not yet know the value of in the request scanning phase.

	returnValIfTrigger := !ruleItem.Predicate.Neg

	isTxTarget := target.Name == ast.TargetTx
	var isTxTargetPresent bool
	if isTxTarget {
		if target.IsRegexSelector {
			isTxTargetPresent = len(env.GetTxVarsViaRegexSelector(target.Selector)) > 0
		} else {
			isTxTargetPresent = env.Get(ast.EnvVarTx, strings.ToLower(target.Selector)) != nil
		}
	}

	if isTxTarget && !isTxTargetPresent && !target.IsCount {
		// This is a tx variable that is not set
		result = false
		return
	}

	var triggered bool
	triggered, match, err = eval(ruleItem.Predicate, target, scanResults, env)
	if triggered {
		result = returnValIfTrigger
		return
	}

	result = !returnValIfTrigger
	return
}

// We require a late scan (a scan in the eval phase as opposed to the req scan phase) if either left or right side was not known in the scan phase.
func requiresLateScan(predicate ast.RulePredicate, target ast.Target) bool {
	switch target.Name {
	case ast.TargetMatchedVar, ast.TargetMatchedVars, ast.TargetMatchedVarName, ast.TargetMatchedVarsNames, ast.TargetTx, ast.TargetReqbodyProcessor:
		return true
	}

	if target.IsCount {
		return true
	}

	if predicate.Val.HasMacros() {
		return true
	}

	return false
}
