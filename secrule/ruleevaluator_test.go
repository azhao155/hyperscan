package secrule

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRuleEvaluatorNonDisruptive(t *testing.T) {
	sv, _ := newSetVarAction("tx.anomaly_score=+%{tx.critical_anomaly_score}")
	rules := []Rule{
		{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "ab+c"},
					Transformations: []Transformation{Lowercase, RemoveWhitespace},
					Actions:         []actionHandler{sv},
				},
			},
		},
	}

	assert := assert.New(t)
	key := rxMatchKey{100, 0, "ARGS"}
	m := make(map[rxMatchKey]RxMatch)
	m[key] = RxMatch{StartPos: 0, EndPos: 10, Data: []byte{}}
	sr := ScanResults{m}

	ref := NewRuleEvaluatorFactory()
	re := ref.NewRuleEvaluator(newEnvMap())

	pass, code, err := re.Process(rules, sr)
	assert.Nil(err)
	assert.True(pass)
	assert.Equal(200, code)
}

func TestRuleEvaluatorDisruptive(t *testing.T) {
	sv, _ := newSetVarAction("tx.anomaly_score=+%{tx.critical_anomaly_score}")
	rules := []Rule{
		{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "ab+c"},
					Transformations: []Transformation{Lowercase, RemoveWhitespace},
					Actions:         []actionHandler{sv, newDenyAction()},
				},
			},
		},
	}

	assert := assert.New(t)
	key := rxMatchKey{100, 0, "ARGS"}
	m := make(map[rxMatchKey]RxMatch)
	m[key] = RxMatch{StartPos: 0, EndPos: 10, Data: []byte{}}
	sr := ScanResults{m}

	ref := NewRuleEvaluatorFactory()
	re := ref.NewRuleEvaluator(newEnvMap())

	pass, code, err := re.Process(rules, sr)
	assert.Nil(err)
	assert.False(pass)
	assert.Equal(403, code)
}
