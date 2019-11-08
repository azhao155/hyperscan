package secrule

import (
	"azwaf/waf"
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
		var msg string

		// This runs the actions that need to run after each rule item had a target that triggered
		runActions := func(actions []Action) {
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
					if evalPredicate(perRequestEnv, ruleItem, target, scanResults, stmt, curRuleItemIdx) {
						// Some actions are to be run after each rule item.
						runActions(ruleItem.Actions)

						// Some actions are only to be run when all rule items triggered.
						if curRuleItemIdx == len(stmt.Items)-1 {
							for _, r := range stmt.Items {
								runActionsAfterAllRuleItemsTriggered(r.Actions)
							}

							if shouldLog {
								// TODO implement the "logdata" action, so we can put something better than "" in logData
								triggeredCb(stmt, phaseDisruptive, msg, "")
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
			runActions(stmt.Actions)
			runActionsAfterAllRuleItemsTriggered(stmt.Actions)

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

func evalPredicate(env envMap, ruleItem RuleItem, target Target, scanResults *ScanResults, rule *Rule, curRuleItemIdx int) bool {
	isTxTarget := strings.EqualFold(target.Name, "tx")
	isTxTargetPresent := isTxTarget && env.hasKey(target.Name+"."+target.Selector)

	if target.IsCount {
		// Count-targets are special. They can be used to check in SecRule-lang whether a target was present. Therefore don't skip for now.
		// TODO fully handle count-targets
	} else if isTxTarget {
		if !isTxTargetPresent {
			return false
		}
	} else {
		// Targets that we never even came across
		if scanResults.targetsCount[target] == 0 {
			return false
		}
	}

	toReturnIfTrigger := !ruleItem.Predicate.Neg
	switch ruleItem.Predicate.Op {
	case Rx, Pm, Pmf, PmFromFile, BeginsWith, EndsWith, Contains, ContainsWord, Strmatch, Streq, Within, DetectXSS, ValidateURLEncoding:
		_, ok := scanResults.GetResultsFor(rule.ID, curRuleItemIdx, target)
		if ok {
			return toReturnIfTrigger
		}

		if len(ruleItem.Predicate.valMacroMatches) > 0 {
			matchFound, _, _ := ruleItem.Predicate.eval(scanResults, env)
			if matchFound {
				return toReturnIfTrigger
			}
		}
	case Eq, Ge, Gt, Le, Lt:
		matchFound, _, _ := ruleItem.Predicate.eval(scanResults, env)
		if matchFound {
			return toReturnIfTrigger
		}
	}

	return !toReturnIfTrigger
}
