package secrule

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRuleEvaluatorNonDisruptiveAction(t *testing.T) {
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
	sr := &ScanResults{m}

	ref := NewRuleEvaluatorFactory()
	re := ref.NewRuleEvaluator(newEnvMap())

	pass, code, err := re.Process(rules, sr)
	assert.Nil(err)
	assert.True(pass)
	assert.Equal(200, code)
}

func TestRuleEvaluatorDisruptiveAction(t *testing.T) {
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
	sr := &ScanResults{m}

	ref := NewRuleEvaluatorFactory()
	re := ref.NewRuleEvaluator(newEnvMap())

	pass, code, err := re.Process(rules, sr)
	assert.Nil(err)
	assert.False(pass)
	assert.Equal(403, code)
}

func TestRuleEvaluatorNumericalOperator(t *testing.T) {
	assert := assert.New(t)
	rules := []Rule{
		{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []string{"TX:ANOMALY_SCORE"}, Op: Ge, Val: "%{tx.inbound_anomaly_threshold}", OpFunc: toOperatorFunc(Ge)},
					Transformations: []Transformation{None},
					Actions:         []actionHandler{newDenyAction()},
				},
			},
		},
	}

	p := &rules[0].Items[0].Predicate
	p.valMacroMatches = variableMacroRegex.FindAllStringSubmatch(p.Val, -1)

	ref := NewRuleEvaluatorFactory()
	em := newEnvMap()
	em.set("tx.anomaly_score", &integerObject{Value: 10})
	em.set("tx.inbound_anomaly_threshold", &integerObject{Value: 5})
	re := ref.NewRuleEvaluator(em)

	allow, code, err := re.Process(rules, &ScanResults{})
	assert.Nil(err)
	assert.False(allow)
	assert.Equal(403, code)
}

func TestRuleEvaluatorChain(t *testing.T) {
	// Arrange
	assert := assert.New(t)
	rules := []Rule{
		{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "abc"},
				},
				{
					Predicate: RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "def"},
					Actions:   []actionHandler{newDenyAction()},
				},
			},
		},
	}
	m := make(map[rxMatchKey]RxMatch)
	m[rxMatchKey{100, 0, "ARGS"}] = RxMatch{}
	m[rxMatchKey{100, 1, "ARGS"}] = RxMatch{}
	sr := &ScanResults{m}
	ref := NewRuleEvaluatorFactory()
	re := ref.NewRuleEvaluator(newEnvMap())

	// Act
	pass, code, err := re.Process(rules, sr)

	// Assert
	assert.Nil(err)
	assert.False(pass)
	assert.Equal(403, code)
}

func TestRuleEvaluatorChainNegative(t *testing.T) {
	// Arrange
	assert := assert.New(t)
	rules := []Rule{
		{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "abc"},
				},
				{
					Predicate: RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "def"},
					Actions:   []actionHandler{newDenyAction()},
				},
			},
		},
	}
	m := make(map[rxMatchKey]RxMatch)
	m[rxMatchKey{100, 1, "ARGS"}] = RxMatch{}
	sr := &ScanResults{m}
	ref := NewRuleEvaluatorFactory()
	re := ref.NewRuleEvaluator(newEnvMap())

	// Act
	pass, code, err := re.Process(rules, sr)

	// Assert
	assert.Nil(err)
	assert.True(pass)
	assert.Equal(200, code)
}
