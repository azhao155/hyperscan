package secrule

// RuleEvaluator processes the incoming request against all parsed rules
type ruleEvaluator interface {
	Process(rules []Rule) (err error)
}

type ruleEvaluatorImpl struct {
}

func (r *ruleEvaluatorImpl) Process(rules []Rule) (err error) {
	for curRuleIdx := range rules {
		for curRuleItemIdx := range rules[curRuleIdx].Items {
			for actionIdx := range rules[curRuleIdx].Items[curRuleItemIdx].Actions {
				// TODO: Handle chaining correctly
				rules[curRuleIdx].Items[curRuleItemIdx].Actions[actionIdx].Execute()
			}
		}
	}
	return nil
}