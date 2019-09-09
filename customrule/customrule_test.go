package customrule

import (
	"azwaf/secrule"
	"azwaf/waf"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToSimpleSecRule(t *testing.T) {
	assert := assert.New(t)
	cr := mockCustomRule{
		name:     "blockEvilBot",
		priority: 2,
		ruleType: "MatchRule",
		action:   "Block",
		matchConditions: []waf.MatchCondition{
			mockMatchCondition{
				matchVariables: []waf.MatchVariable{
					mockMatchVariable{
						variableName: "RequestHeaders",
						selector:     "User-Agent",
					},
				},

				operator:        "Contains",
				negateCondition: true,
				matchValues: []string{
					"evilbot",
				},

				transforms: []string{
					"Lowercase",
				},
			},
		},
	}

	st, err := toSecRule(cr)
	assert.Nil(err)

	esr := &secrule.Rule{
		ID:    cr.Priority(),
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
	cr := mockCustomRule{
		name:     "blockEvilBot",
		priority: 2,
		ruleType: "MatchRule",
		action:   "Block",
		matchConditions: []waf.MatchCondition{
			mockMatchCondition{
				matchVariables: []waf.MatchVariable{
					mockMatchVariable{
						variableName: "RequestHeaders",
						selector:     "User-Agent",
					},
				},

				operator:        "Contains",
				negateCondition: true,
				matchValues:     []string{"evilbot", "badbot"},

				transforms: []string{
					"Lowercase",
					"Trim",
				},
			},
			mockMatchCondition{
				matchVariables: []waf.MatchVariable{
					mockMatchVariable{
						variableName: "RemoteAddr",
					},
				},

				operator:        "IPMatch",
				negateCondition: false,
				matchValues:     []string{"192.168.0.1", "192.168.0.2"},

				transforms: []string{},
			},
		},
	}

	st, err := toSecRule(cr)
	assert.Nil(err)

	esr := &secrule.Rule{
		ID:    cr.Priority(),
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
	mv1 := &mockMatchVariable{
		variableName: "RequestCookies",
		selector:     "C1",
	}

	mv2 := &mockMatchVariable{
		variableName: "RequestHeaders",
	}

	at1, _ := toSecRuleTarget(mv1)
	assert.Equal("REQUEST_COOKIES:C1", at1)

	at2, _ := toSecRuleTarget(mv2)
	assert.Equal("REQUEST_HEADERS", at2)
}

func TestToSecruleMatchValueIpMatch(t *testing.T) {
	assert := assert.New(t)
	mc1 := &mockMatchCondition{
		operator: "IPMatch",
		matchValues: []string{
			"192.168.0.1",
		},
	}

	av1 := toSecRuleMatchValue(mc1)
	assert.Equal("192.168.0.1", av1)

	mc2 := &mockMatchCondition{
		operator: "IPMatch",
		matchValues: []string{
			"192.168.0.1",
			"192.168.0.2",
		},
	}

	av2 := toSecRuleMatchValue(mc2)
	assert.Equal("192.168.0.1,192.168.0.2", av2)
}

func TestToSecruleMatchValueContains(t *testing.T) {
	assert := assert.New(t)
	mc1 := &mockMatchCondition{
		operator: "Contains",
		matchValues: []string{
			"str1",
		},
	}

	av1 := toSecRuleMatchValue(mc1)
	assert.Equal("(str1)", av1)

	mc2 := &mockMatchCondition{
		operator: "Contains",
		matchValues: []string{
			"str1",
			"str2",
		},
	}

	av2 := toSecRuleMatchValue(mc2)
	assert.Equal("(str1|str2)", av2)
}

func TestToSecruleMatchValueBeginsWith(t *testing.T) {
	assert := assert.New(t)
	mc1 := &mockMatchCondition{
		operator: "BeginsWith",
		matchValues: []string{
			"str1",
		},
	}

	av1 := toSecRuleMatchValue(mc1)
	assert.Equal("^(str1)", av1)

	mc2 := &mockMatchCondition{
		operator: "BeginsWith",
		matchValues: []string{
			"str1",
			"str2",
		},
	}

	av2 := toSecRuleMatchValue(mc2)
	assert.Equal("^(str1|str2)", av2)
}

func TestToSecruleMatchValueEndsWith(t *testing.T) {
	assert := assert.New(t)
	mc1 := &mockMatchCondition{
		operator: "EndsWith",
		matchValues: []string{
			"str1",
		},
	}

	av1 := toSecRuleMatchValue(mc1)
	assert.Equal("(str1)$", av1)

	mc2 := &mockMatchCondition{
		operator: "EndsWith",
		matchValues: []string{
			"str1",
			"str2",
		},
	}

	av2 := toSecRuleMatchValue(mc2)
	assert.Equal("(str1|str2)$", av2)
}

func TestToSecruleMatchValueEquals(t *testing.T) {
	assert := assert.New(t)
	mc1 := &mockMatchCondition{
		operator: "Equals",
		matchValues: []string{
			"str1",
		},
	}

	av1 := toSecRuleMatchValue(mc1)
	assert.Equal("^(str1)$", av1)

	mc2 := &mockMatchCondition{
		operator: "Equals",
		matchValues: []string{
			"str1",
			"str2",
		},
	}

	av2 := toSecRuleMatchValue(mc2)
	assert.Equal("^(str1|str2)$", av2)
}

func TestToSecruleMatchValueLessThan(t *testing.T) {
	assert := assert.New(t)
	mc1 := &mockMatchCondition{
		operator: "LessThan",
		matchValues: []string{
			"12",
		},
	}

	av1 := toSecRuleMatchValue(mc1)
	assert.Equal("12", av1)

	mc2 := &mockMatchCondition{
		operator: "LessThan",
		matchValues: []string{
			"12",
			"15",
		},
	}

	av2 := toSecRuleMatchValue(mc2)
	assert.Equal("15", av2)
}

func TestToSecruleMatchValueLessThanOrEqual(t *testing.T) {
	assert := assert.New(t)
	mc1 := mockMatchCondition{
		operator: "LessThanOrEqual",
		matchValues: []string{
			"12",
		},
	}

	av1 := toSecRuleMatchValue(mc1)
	assert.Equal("12", av1)

	mc2 := &mockMatchCondition{
		operator: "LessThanOrEqual",
		matchValues: []string{
			"12",
			"15",
		},
	}

	av2 := toSecRuleMatchValue(mc2)
	assert.Equal("15", av2)
}

func TestToSecruleMatchValueGreaterThan(t *testing.T) {
	assert := assert.New(t)
	mc1 := &mockMatchCondition{
		operator: "GreaterThan",
		matchValues: []string{
			"12",
		},
	}

	av1 := toSecRuleMatchValue(mc1)
	assert.Equal("12", av1)

	mc2 := &mockMatchCondition{
		operator: "GreaterThan",
		matchValues: []string{
			"12",
			"15",
		},
	}

	av2 := toSecRuleMatchValue(mc2)
	assert.Equal("12", av2)
}

func TestToSecruleMatchValueGreaterThanOrEqual(t *testing.T) {
	assert := assert.New(t)
	mc1 := mockMatchCondition{
		operator: "GreaterThanOrEqual",
		matchValues: []string{
			"12",
		},
	}

	av1 := toSecRuleMatchValue(mc1)
	assert.Equal("12", av1)

	mc2 := mockMatchCondition{
		operator: "GreaterThanOrEqual",
		matchValues: []string{
			"12",
			"15",
		},
	}

	av2 := toSecRuleMatchValue(mc2)
	assert.Equal("12", av2)
}
