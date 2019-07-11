package secrule

import "azwaf/waf"

func newMockRuleLoader() RuleLoader {
	return &mockRuleLoader{}
}

type mockRuleLoader struct{}

func (m *mockRuleLoader) Rules(r waf.RuleSetID) (statements []Statement, err error) {
	statements = []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "ab+c"},
					Transformations: []Transformation{},
				},
			},
		},
		&Rule{
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
		&Rule{
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
