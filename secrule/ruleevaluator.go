package secrule

// RuleEvaluator processes the incoming request against all parsed rules
type RuleEvaluator interface {
	Process(rules []Rule, scanResults ScanResults) (allow bool, statusCode int, err error)
}

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

func (r ruleEvaluatorImpl) Process(rules []Rule, scanResults ScanResults) (bool, int, error) {
	for curRuleIdx := range rules {
		rule := rules[curRuleIdx]
		for curRuleItemIdx := range rules[curRuleIdx].Items {

			ruleItem := rules[curRuleIdx].Items[curRuleItemIdx]
			matchFound := false

			for _, target := range ruleItem.Predicate.Targets {
				switch ruleItem.Predicate.Op {
				case Rx, Pmf, PmFromFile:
					_, ok := scanResults.GetRxResultsFor(rule.ID, curRuleItemIdx, target)
					if ok {
						matchFound = true
					}
				case Eq, Ge, Gt, Le, Lt:
					matchFound, _, _ = ruleItem.Predicate.eval(r.perRequestEnv)
				}
			}

			if matchFound {
				for actionIdx := range ruleItem.Actions {
					// TODO: Handle chaining correctly
					ar := ruleItem.Actions[actionIdx].execute(r.perRequestEnv)
					// Not letting action related events affect the WAF decision as of now.
					if ruleItem.Actions[actionIdx].isDisruptive() {
						return ar.allow, ar.statusCode, nil
					}
				}
			}

		}
	}
	return true, 200, nil
}
