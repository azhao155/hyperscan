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
	// The triggered callback is optional. Default to do nothing.
	if triggeredCb == nil {
		triggeredCb = func(stmt Statement, isDisruptive bool, msg string, logData string) {}
	}

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

		var actions []Action
		var stmtID int
		var triggered bool
		shouldLog := true
		var msg string

		runActionsAfterSingleRuleItem := func(actions []Action) {
			// TODO implement the "pass" action. If there are X many matches, the pass action is supposed to make all actions execute X many times.

			for _, action := range actions {
				switch action := action.(type) {

				case *SetVarAction:
					err := executeSetVarAction(action, perRequestEnv)
					if err != nil {
						logger.Warn().Int("ruleID", stmtID).Err(err).Msg("Error executing setVar action")
					}
				}
			}
		}

		switch stmt := stmt.(type) {
		case *Rule:
			triggered = false
			stmtID = stmt.ID

			for curRuleItemIdx, ruleItem := range stmt.Items {
				if evalPredicate(perRequestEnv, ruleItem, scanResults, stmt, curRuleItemIdx) {
					triggered = true
					runActionsAfterSingleRuleItem(ruleItem.Actions) // Some actions are to be run after each chain item.
					actions = append(actions, ruleItem.Actions...)  // Other actions later, only when all chain items triggered.
				} else {
					triggered = false
					break
				}
			}

		case *ActionStmt:
			triggered = true
			stmtID = stmt.ID
			actions = stmt.Actions
			runActionsAfterSingleRuleItem(actions)
		}

		if triggered {
			logger.Debug().Int("ruleID", stmtID).Msg("Rule triggered")

			// Some actions are to be run after all rule items in the chain triggered.
			for _, action := range actions {
				switch action := action.(type) {

				case *SkipAfterAction:
					skipAfter = action.Label
					logger.Debug().Str("label", skipAfter).Msg("Skipping to marker")

				case *NoLogAction:
					shouldLog = false

				case *LogAction:
					shouldLog = true

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
	anyMatched := false
	anyChecked := false

	for _, target := range ruleItem.Predicate.Targets {
		isTxTarget := strings.EqualFold(target.Name, "tx")
		isTxTargetPresent := isTxTarget && env.hasKey(target.Name+"."+target.Selector)

		// For targets that we never even came across, we just always skip the predicate like ModSec does
		if target.IsCount {
			// Count-targets are special. They can be used to check in SecRule-lang whether a target was present. Therefore don't skip for now.
			// TODO fully handle count-targets
		} else if isTxTarget {
			if !isTxTargetPresent {
				continue
			}
		} else {
			if scanResults.targetsCount[target] == 0 {
				continue
			}
		}

		anyChecked = true

		switch ruleItem.Predicate.Op {
		case Rx, Pm, Pmf, PmFromFile, BeginsWith, EndsWith, Contains, ContainsWord, Strmatch, Streq, Within, DetectXSS, ValidateURLEncoding:
			_, ok := scanResults.GetResultsFor(rule.ID, curRuleItemIdx, target)
			if ok {
				anyMatched = true
				break
			}

			if len(ruleItem.Predicate.valMacroMatches) > 0 {
				matchFound, _, _ := ruleItem.Predicate.eval(scanResults, env)
				if matchFound {
					anyMatched = true
					break
				}
			}
		case Eq, Ge, Gt, Le, Lt:
			matchFound, _, _ := ruleItem.Predicate.eval(scanResults, env)
			anyMatched = anyMatched || matchFound
			if matchFound {
				break
			}
		}
	}

	if !anyChecked {
		return false
	}

	if ruleItem.Predicate.Neg {
		return !anyMatched
	}

	return anyMatched
}
