package customrule

import (
	"azwaf/secrule"
	"azwaf/testutils"
	"azwaf/waf"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadCustomRulesReorder(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	rl := ruleLoader{}

	cr := mockCustomRuleConfig{
		customRules: []waf.CustomRule{
			mockCustomRule{
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
						negateCondition: false,
						matchValues:     []string{"evilbot"},
						transforms:      []string{"Lowercase"},
					},
				},
			},
			mockCustomRule{
				name:     "blockEvilBot",
				priority: 1,
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
						negateCondition: false,
						matchValues:     []string{"evilbot"},
						transforms:      []string{"Lowercase"},
					},
				},
			},
		},
	}

	rr := rl.loadCustomRules(logger, cr)

	assert.Equal(1, rr[0].Priority())
	assert.Equal(2, rr[1].Priority())
}

func TestGetSecRules(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)
	rl := ruleLoader{}

	cr := mockCustomRuleConfig{
		customRules: []waf.CustomRule{
			mockCustomRule{
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
						negateCondition: false,
						matchValues:     []string{"evilbot"},
						transforms:      []string{"Lowercase"},
					},
				},
			},
			mockCustomRule{
				name:     "blockEvilBot",
				priority: 1,
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
						negateCondition: false,
						matchValues:     []string{"evilbot"},
						transforms:      []string{"Lowercase"},
					},
				},
			},
		},
	}

	ss, err := rl.GetSecRules(logger, cr)
	assert.Nil(err)
	assert.Equal(2, len(ss))

	r1 := ss[0].(*secrule.Rule)
	assert.NotNil(r1)
	assert.Equal(1, r1.ID)

	r2 := ss[1].(*secrule.Rule)
	assert.NotNil(r2)
	assert.Equal(2, r2.ID)
}
