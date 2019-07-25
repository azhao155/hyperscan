package customrule

import (
	"azwaf/testutils"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetRulesUnmarshal(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)
	rl := ruleLoader{}
	cr := `[
	{
		"name": "blockEvilBot",
		"priority": 2,
		"ruleType": "MatchRule",
		"action": "Block",
		"matchConditions": [
		{
			"matchVariables": [
			{
				"variableName": "RequestHeaders",
				"selector": "User-Agent"
			}
		],
			"operator": "Contains",
			"negationConditon": false,
			"matchValues": [
			"evilbot"
		],
			"transforms": [
			"Lowercase"
		]
		}
	]}]`

	rr, err := rl.GetRules(logger, cr)
	assert.Nil(err)

	expected := CustomRule{
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
				Negate:   false,
				MatchValues: []string{
					"evilbot",
				},

				Transforms: []string{
					"Lowercase",
				},
			},
		},
	}

	assert.Equal([]CustomRule{expected}, rr)

}

func TestGetRulesReorder(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	rl := ruleLoader{}
	cr := `[
	{
		"name": "blockEvilBot",
		"priority": 2,
		"ruleType": "MatchRule",
		"action": "Block",
		"matchConditions": [
		{
			"matchVariables": [
			{
				"variableName": "RequestHeaders",
				"selector": "User-Agent"
			}
			],
			"operator": "Contains",
			"negationConditon": false,
			"matchValues": [
			"evilbot"
			],
			"transforms": [
			"Lowercase"
			]
		}
	]},

		{
		"name": "blockEvilBot",
		"priority": 1,
		"ruleType": "MatchRule",
		"action": "Block",
		"matchConditions": [
		{
			"matchVariables": [
			{
				"variableName": "RequestHeaders",
				"selector": "User-Agent"
			}
		],
			"operator": "Contains",
			"negationConditon": false,
			"matchValues": [
			"evilbot"
			],
			"transforms": [
			"Lowercase"
			]
		}
	]}
	]`

	rr, err := rl.GetRules(logger, cr)
	assert.Nil(err)

	assert.Equal(1, rr[0].Priority)
	assert.Equal(2, rr[1].Priority)
}

func TestGetRulesNegative(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)
	rl := ruleLoader{}
	cr := `[
	{
		"name": "blockEvilBot",
		"priority": 2,
		"ruleType": "MatchRule",
		"action": "Block",
		"matchConditions": `

	_, err := rl.GetRules(logger, cr)
	assert.NotNil(err)
}
