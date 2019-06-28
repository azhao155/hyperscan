package secrule

import "azwaf/waf"

func newMockRuleLoader() RuleLoader {
	return &mockRuleLoader{}
}

type mockRuleLoader struct{}

func (m *mockRuleLoader) Rules(r waf.RuleSetID) (rules []Rule, err error) {
	rules = []Rule{
		{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "ab+c"},
					Transformations: []Transformation{},
				},
			},
		},
		{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "abc+"},
					Transformations: []Transformation{},
				},
				{
					Predicate:       RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "xyz"},
					Transformations: []Transformation{Lowercase},
				},
			},
		},
		{
			ID: 300,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []string{"REQUEST_URI_RAW"}, Op: Rx, Val: "a+bc"},
					Transformations: []Transformation{Lowercase, RemoveWhitespace},
				},
			},
		},
	}

	return
}
