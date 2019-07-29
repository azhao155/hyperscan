package customrule

import (
	"azwaf/secrule"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestToSimpleSecRule(t *testing.T) {
	assert := assert.New(t)
	cr := CustomRule{
		Name:     "blockEvilBot",
		Priority: 2,
		RuleType: "MatchRule",
		Action:   "Block",
		MatchConditions: []MatchCondition{
			{
				MatchVariables: []MatchVariable{
					{
						VariableName: "RequestHeaders",
						Selector:     "User-Agent",
					},
				},

				Operator: "Contains",
				Negate:   true,
				MatchValues: []string{
					"evilbot",
				},

				Transforms: []string{
					"Lowercase",
				},
			},
		},
	}

	st, err := cr.toSecRule()
	assert.Nil(err)

	esr := &secrule.Rule{
		ID:    cr.Priority,
		Phase: 0,
		Items: []secrule.RuleItem{
			{
				Predicate:       secrule.RulePredicate{Targets: []string{"REQUEST_HEADERS:User-Agent"}, Neg: true, Op: secrule.Rx, Val: "(evilbot)"},
				Transformations: []secrule.Transformation{secrule.Lowercase},
				Actions:         []secrule.Action{&secrule.BlockAction{}},
			},
		},
	}

	asr := st.(*secrule.Rule)

	assert.Equal(esr, asr)
}

func TestToSecRuleWithMultiples(t *testing.T) {
	assert := assert.New(t)
	cr := CustomRule{
		Name:     "blockEvilBot",
		Priority: 2,
		RuleType: "MatchRule",
		Action:   "Block",
		MatchConditions: []MatchCondition{
			{
				MatchVariables: []MatchVariable{
					{
						VariableName: "RequestHeaders",
						Selector:     "User-Agent",
					},
				},

				Operator: "Contains",
				Negate:   true,
				MatchValues: []string{
					"evilbot",
					"badbot",
				},

				Transforms: []string{
					"Lowercase",
					"Trim",
				},
			},
			{
				MatchVariables: []MatchVariable{
					{
						VariableName: "RemoteAddr",
					},
				},

				Operator: "IPMatch",
				Negate:   false,
				MatchValues: []string{
					"192.168.0.1", "192.168.0.2",
				},

				Transforms: []string{},
			},
		},
	}

	st, err := cr.toSecRule()
	assert.Nil(err)

	esr := &secrule.Rule{
		ID:    cr.Priority,
		Phase: 0,
		Items: []secrule.RuleItem{
			{
				Predicate:       secrule.RulePredicate{Targets: []string{"REQUEST_HEADERS:User-Agent"}, Neg: true, Op: secrule.Rx, Val: "(evilbot|badbot)"},
				Transformations: []secrule.Transformation{secrule.Lowercase, secrule.Trim},
				Actions:         []secrule.Action{&secrule.BlockAction{}},
			},
			{
				Predicate:       secrule.RulePredicate{Targets: []string{"REMOTE_ADDR"}, Neg: false, Op: secrule.IPMatch, Val: "192.168.0.1,192.168.0.2"},
				Transformations: nil,
			},
		},
	}

	asr := st.(*secrule.Rule)

	assert.Equal(esr, asr)
}

func TestToSecruleTarget(t *testing.T) {
	assert := assert.New(t)
	mv1 := &MatchVariable{
		VariableName: "RequestCookies",
		Selector:     "C1",
	}

	mv2 := &MatchVariable{
		VariableName: "RequestHeaders",
	}

	at1, _ := mv1.toSecRuleTarget()
	assert.Equal("REQUEST_COOKIES:C1", at1)

	at2, _ := mv2.toSecRuleTarget()
	assert.Equal("REQUEST_HEADERS", at2)
}

func TestToSecruleMatchValueIpMatch(t *testing.T) {
	assert := assert.New(t)
	mc1 := &MatchCondition{
		Operator: "IPMatch",
		MatchValues: []string{
			"192.168.0.1",
		},
	}

	av1 := mc1.toSecRuleMatchValue()
	assert.Equal("192.168.0.1", av1)

	mc2 := &MatchCondition{
		Operator: "IPMatch",
		MatchValues: []string{
			"192.168.0.1",
			"192.168.0.2",
		},
	}

	av2 := mc2.toSecRuleMatchValue()
	assert.Equal("192.168.0.1,192.168.0.2", av2)
}

func TestToSecruleMatchValueContains(t *testing.T) {
	assert := assert.New(t)
	mc1 := &MatchCondition{
		Operator: "Contains",
		MatchValues: []string{
			"str1",
		},
	}

	av1 := mc1.toSecRuleMatchValue()
	assert.Equal("(str1)", av1)

	mc2 := &MatchCondition{
		Operator: "Contains",
		MatchValues: []string{
			"str1",
			"str2",
		},
	}

	av2 := mc2.toSecRuleMatchValue()
	assert.Equal("(str1|str2)", av2)
}

func TestToSecruleMatchValueBeginsWith(t *testing.T) {
	assert := assert.New(t)
	mc1 := &MatchCondition{
		Operator: "BeginsWith",
		MatchValues: []string{
			"str1",
		},
	}

	av1 := mc1.toSecRuleMatchValue()
	assert.Equal("^(str1)", av1)

	mc2 := &MatchCondition{
		Operator: "BeginsWith",
		MatchValues: []string{
			"str1",
			"str2",
		},
	}

	av2 := mc2.toSecRuleMatchValue()
	assert.Equal("^(str1|str2)", av2)
}

func TestToSecruleMatchValueEndsWith(t *testing.T) {
	assert := assert.New(t)
	mc1 := &MatchCondition{
		Operator: "EndsWith",
		MatchValues: []string{
			"str1",
		},
	}

	av1 := mc1.toSecRuleMatchValue()
	assert.Equal("(str1)$", av1)

	mc2 := &MatchCondition{
		Operator: "EndsWith",
		MatchValues: []string{
			"str1",
			"str2",
		},
	}

	av2 := mc2.toSecRuleMatchValue()
	assert.Equal("(str1|str2)$", av2)
}

func TestToSecruleMatchValueEquals(t *testing.T) {
	assert := assert.New(t)
	mc1 := &MatchCondition{
		Operator: "Equals",
		MatchValues: []string{
			"str1",
		},
	}

	av1 := mc1.toSecRuleMatchValue()
	assert.Equal("^(str1)$", av1)

	mc2 := &MatchCondition{
		Operator: "Equals",
		MatchValues: []string{
			"str1",
			"str2",
		},
	}

	av2 := mc2.toSecRuleMatchValue()
	assert.Equal("^(str1|str2)$", av2)
}

func TestToSecruleMatchValueLessThan(t *testing.T) {
	assert := assert.New(t)
	mc1 := &MatchCondition{
		Operator: "LessThan",
		MatchValues: []string{
			"12",
		},
	}

	av1 := mc1.toSecRuleMatchValue()
	assert.Equal("12", av1)

	mc2 := &MatchCondition{
		Operator: "LessThan",
		MatchValues: []string{
			"12",
			"15",
		},
	}

	av2 := mc2.toSecRuleMatchValue()
	assert.Equal("15", av2)
}

func TestToSecruleMatchValueLessThanOrEqual(t *testing.T) {
	assert := assert.New(t)
	mc1 := &MatchCondition{
		Operator: "LessThanOrEqual",
		MatchValues: []string{
			"12",
		},
	}

	av1 := mc1.toSecRuleMatchValue()
	assert.Equal("12", av1)

	mc2 := &MatchCondition{
		Operator: "LessThanOrEqual",
		MatchValues: []string{
			"12",
			"15",
		},
	}

	av2 := mc2.toSecRuleMatchValue()
	assert.Equal("15", av2)
}

func TestToSecruleMatchValueGreaterThan(t *testing.T) {
	assert := assert.New(t)
	mc1 := &MatchCondition{
		Operator: "GreaterThan",
		MatchValues: []string{
			"12",
		},
	}

	av1 := mc1.toSecRuleMatchValue()
	assert.Equal("12", av1)

	mc2 := &MatchCondition{
		Operator: "GreaterThan",
		MatchValues: []string{
			"12",
			"15",
		},
	}

	av2 := mc2.toSecRuleMatchValue()
	assert.Equal("12", av2)
}

func TestToSecruleMatchValueGreaterThanOrEqual(t *testing.T) {
	assert := assert.New(t)
	mc1 := &MatchCondition{
		Operator: "GreaterThanOrEqual",
		MatchValues: []string{
			"12",
		},
	}

	av1 := mc1.toSecRuleMatchValue()
	assert.Equal("12", av1)

	mc2 := &MatchCondition{
		Operator: "GreaterThanOrEqual",
		MatchValues: []string{
			"12",
			"15",
		},
	}

	av2 := mc2.toSecRuleMatchValue()
	assert.Equal("12", av2)
}
