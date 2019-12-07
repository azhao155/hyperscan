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

	// Evaluate each of secrule-lang's five phases, but stop if there was a disruptive action.
	for phase := 1; phase <= 5; phase++ {
		logger.Debug().Int("phase", phase).Msg("Starting rule evaluation phase")

		p := phaseEvaluation{
			logger:        logger,
			phase:         phase,
			perRequestEnv: perRequestEnv,
			statements:    statements,
			scanResults:   scanResults,
			triggeredCb:   triggeredCb,
		}

		if phase == 5 {
			// Phase 5 is special, because it cannot perform any disruptive actions.
			p.processPhase()
			continue
		}

		var phaseDisruptive = false
		decision, statusCode, phaseDisruptive = p.processPhase()
		if phaseDisruptive {
			break
		}
	}

	return
}

type phaseEvaluation struct {
	phase               int
	logger              zerolog.Logger
	perRequestEnv       environment
	statements          []Statement
	scanResults         *ScanResults
	triggeredCb         RuleEvaluatorTriggeredCb
	cleanUpCapturedVars func()
	skipAfter           string
	stmtID              int
	shouldLog           bool
	msg                 Value
	logData             Value
	decision            waf.Decision
	statusCode          int
	phaseDisruptive     bool
}

func (p *phaseEvaluation) processPhase() (decision waf.Decision, statusCode int, phaseDisruptive bool) {
	p.decision = waf.Pass
	p.statusCode = 200
	p.phaseDisruptive = false

	defer func() {
		if p.cleanUpCapturedVars != nil {
			p.cleanUpCapturedVars()
		}
	}()

	for _, stmt := range p.statements {
		// If we are currently looking for a skipAfter marker, then keep skipping until we find it.
		if p.skipAfter != "" {
			if m, ok := stmt.(*Marker); ok {
				if m.Label == p.skipAfter {
					p.skipAfter = ""
				}
			}

			continue
		}

		// Are we in the right phase for this statement?
		if checkPhaseShouldContinue(p.phase, stmt) {
			continue
		}

		p.shouldLog = true
		p.stmtID = 0
		p.msg = nil
		p.logData = nil

		switch stmt := stmt.(type) {
		case *Rule:
			p.stmtID = stmt.ID

			p.perRequestEnv.resetMatchesCollections()

			for curRuleItemIdx, ruleItem := range stmt.Items {
				anyRuleItemTriggered := false
				for _, target := range ruleItem.Predicate.Targets {
					triggered, matches, err := evalPredicate(p.perRequestEnv, ruleItem, target, p.scanResults, stmt, curRuleItemIdx)
					if err != nil {
						p.logger.Warn().Int("ruleID", p.stmtID).Int("ruleItemIdx", curRuleItemIdx).Err(err).Msg("Error evaluating predicate")
					}

					if triggered {
						// Update the environment matched_var, matched_vars, etc., for any rule that may need it during late scanning.
						p.perRequestEnv.updateMatches(matches)

						var latestMatch Match
						if len(matches) > 0 {
							latestMatch = matches[len(matches)-1]
						}

						// Some actions are to be run after each rule item.
						p.runActions(ruleItem.Actions, latestMatch)

						// Some actions are only to be run when all rule items triggered.
						if curRuleItemIdx == len(stmt.Items)-1 {
							for _, r := range stmt.Items {
								p.runActionsAfterAllRuleItemsTriggered(r.Actions)
							}

							if p.shouldLog {
								p.triggeredCb(stmt, p.phaseDisruptive, p.msg.expandMacros(p.perRequestEnv).string(), p.logData.expandMacros(p.perRequestEnv).string())
							}

							if p.phaseDisruptive {
								return p.decision, p.statusCode, p.phaseDisruptive
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
			p.stmtID = stmt.ID
			p.runActions(stmt.Actions, Match{})
			p.runActionsAfterAllRuleItemsTriggered(stmt.Actions)

			if p.shouldLog {
				p.triggeredCb(stmt, p.phaseDisruptive, p.msg.expandMacros(p.perRequestEnv).string(), p.logData.expandMacros(p.perRequestEnv).string())
			}

			if p.phaseDisruptive {
				return p.decision, p.statusCode, p.phaseDisruptive
			}
		}

		if p.cleanUpCapturedVars != nil {
			p.cleanUpCapturedVars()
		}
	}

	return p.decision, p.statusCode, p.phaseDisruptive
}

// This runs the actions that need to run after each rule item had a target that triggered
func (p *phaseEvaluation) runActions(actions []Action, match Match) {
	// TODO implement the "pass" action. If there are X many matches, the pass action is supposed to make all actions execute X many times.

	for _, action := range actions {
		switch action := action.(type) {

		case *SetVarAction:
			err := executeSetVarAction(action, p.perRequestEnv)
			if err != nil {
				p.logger.Warn().Int("ruleID", p.stmtID).Err(err).Msg("Error executing setVar action")
			}

		case *NoLogAction:
			p.shouldLog = false

		case *LogAction:
			p.shouldLog = true

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

				p.perRequestEnv.set("tx."+strconv.Itoa(i), Value{t})
			}

			p.cleanUpCapturedVars = func() {
				// Clean up tx.1, tx.2, etc., if they were set
				for i := 0; i < txVarCount; i++ {
					p.perRequestEnv.delete("tx." + strconv.Itoa(i))
				}
				p.cleanUpCapturedVars = nil
			}

		case *CtlAction:
			p.perRequestEnv.set(action.setting, action.value.expandMacros(p.perRequestEnv))
		}
	}
}

// This runs the actions that need to run after all rule items have triggered
func (p *phaseEvaluation) runActionsAfterAllRuleItemsTriggered(actions []Action) {
	p.logger.Debug().Int("ruleID", p.stmtID).Msg("Rule triggered")

	// Some actions are to be run after all rule items in the chain triggered.
	for _, action := range actions {
		switch action := action.(type) {

		case *SkipAfterAction:
			p.skipAfter = action.Label
			p.logger.Debug().Str("label", p.skipAfter).Msg("Skipping to marker")

		case *MsgAction:
			p.msg = action.Msg

		case *LogDataAction:
			p.logData = action.LogData

		case *AllowAction:
			p.phaseDisruptive = true
			p.decision = waf.Allow

		case *DenyAction:
			p.phaseDisruptive = true
			p.decision = waf.Block
			p.statusCode = 403

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
