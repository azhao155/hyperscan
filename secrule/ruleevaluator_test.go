package secrule

import (
	"azwaf/testutils"
	"azwaf/waf"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRuleEvaluatorNonDisruptiveAction(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	sv, _ := parseSetVarAction("tx.anomaly_score=+%{tx.critical_anomaly_score}")
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: "something"},
					Actions:   []Action{sv, &DenyAction{}}, // The predicate will not be satisfied, so this should not run
				},
			},
		},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: "ab+c"},
					Transformations: []Transformation{Lowercase, RemoveWhitespace},
					Actions:         []Action{sv},
				},
			},
		},
	}
	assert := assert.New(t)
	key := matchKey{200, 0, Target{Name: "ARGS"}}
	m := make(map[matchKey]Match)
	m[key] = Match{Data: []byte{}}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, newEnvMap(sr), rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorDisruptiveAction(t *testing.T) {
	logger := testutils.NewTestLogger(t)
	sv, _ := parseSetVarAction("tx.anomaly_score=+%{tx.critical_anomaly_score}")
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: "ab+c"},
					Transformations: []Transformation{Lowercase, RemoveWhitespace},
					Actions:         []Action{sv, &DenyAction{}},
				},
			},
		},
	}

	assert := assert.New(t)
	key := matchKey{100, 0, Target{Name: "ARGS"}}
	m := make(map[matchKey]Match)
	m[key] = Match{Data: []byte{}}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	decision, code, err := re.Process(logger, newEnvMap(sr), rules, sr, cb)
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
	assert.Equal(403, code)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorAllowAction(t *testing.T) {
	logger := testutils.NewTestLogger(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: "ab+c"},
					Transformations: []Transformation{Lowercase, RemoveWhitespace},
					Actions:         []Action{&AllowAction{}},
				},
			},
		},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: "ab+c"},
					Transformations: []Transformation{Lowercase, RemoveWhitespace},
					Actions:         []Action{&DenyAction{}},
				},
			},
		},
	}

	assert := assert.New(t)
	key := matchKey{100, 0, Target{Name: "ARGS"}}
	m := make(map[matchKey]Match)
	m[key] = Match{Data: []byte{}}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	decision, code, err := re.Process(logger, newEnvMap(sr), rules, sr, cb)
	assert.Nil(err)
	assert.Equal(waf.Allow, decision)
	assert.Equal(200, code)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorNumericalOperator(t *testing.T) {
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	p := RulePredicate{Targets: []Target{{Name: "TX", Selector: "ANOMALY_SCORE"}}, Op: Ge, Val: "%{tx.inbound_anomaly_threshold}"}
	p.valMacroMatches = variableMacroRegex.FindAllStringSubmatch(p.Val, -1)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       p,
					Transformations: []Transformation{None},
					Actions:         []Action{&DenyAction{}},
				},
			},
		},
	}

	em := newEnvMap(&ScanResults{})
	em.set("tx.anomaly_score", &integerObject{Value: 10})
	em.set("tx.inbound_anomaly_threshold", &integerObject{Value: 5})
	re := NewRuleEvaluator()

	tc := make(map[Target]int)
	sr := &ScanResults{targetsCount: tc}

	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	decision, code, err := re.Process(logger, em, rules, sr, cb)
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
	assert.Equal(403, code)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorChain(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: "abc"},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: "def"},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	m[matchKey{100, 0, Target{Name: "ARGS"}}] = Match{}
	m[matchKey{100, 1, Target{Name: "ARGS"}}] = Match{}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, newEnvMap(sr), rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
	assert.Equal(403, code)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorChainNegative(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: "abc"},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: "def"},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	m[matchKey{100, 1, Target{Name: "ARGS"}}] = Match{}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, newEnvMap(sr), rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
	assert.Equal(0, cbCalled)
}

func TestRuleEvaluatorChainActionInFirstItemNegative(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: "abc"},
					Actions:   []Action{&DenyAction{}},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: "def"},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	m[matchKey{100, 0, Target{Name: "ARGS"}}] = Match{}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, newEnvMap(sr), rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
	assert.Equal(0, cbCalled)
}

func TestRuleEvaluatorChainDisruptiveInFirstItemAllItemsRun(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	sv1, _ := parseSetVarAction("tx.somevar=123")
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: "abc"},
					Actions:   []Action{&DenyAction{}},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: "def"},
					Actions:   []Action{&sv1},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	m[matchKey{100, 0, Target{Name: "ARGS"}}] = Match{}
	m[matchKey{100, 1, Target{Name: "ARGS"}}] = Match{}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	env := newEnvMap(sr)
	assert.False(env.hasKey("tx.somevar"))
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, env, rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&stringObject{"123"}, v)
	assert.Equal(403, code)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorChainSetVarInFirstItem(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	sv1, _ := parseSetVarAction("tx.somevar=123")
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: "abc"},
					Actions:   []Action{&sv1},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: "shouldNotMatch"},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	m[matchKey{100, 0, Target{Name: "ARGS"}}] = Match{}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	env := newEnvMap(sr)
	assert.False(env.hasKey("tx.somevar"))
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, env, rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&stringObject{"123"}, v)
	assert.Equal(200, code)
	assert.Equal(0, cbCalled)
}

func TestRuleEvaluatorSecAction(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv, _ := parseSetVarAction("tx.somevar=123")
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv}},
	}
	m := make(map[matchKey]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{matches: m, targetsCount: tc}
	env := newEnvMap(sr)
	assert.False(env.hasKey("tx.somevar"))
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, env, rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&stringObject{"123"}, v)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorSetVarString(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1, _ := parseSetVarAction("tx.somevar=a")
	sv2, _ := parseSetVarAction("tx.somevar=%{tx.somevar}b")
	sv3, _ := parseSetVarAction("tx.somevar=%{tx.somevar}c")
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv1}},
		&ActionStmt{ID: 200, Actions: []Action{&sv2}},
		&ActionStmt{ID: 300, Actions: []Action{&sv3}},
	}
	m := make(map[matchKey]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{matches: m, targetsCount: tc}
	env := newEnvMap(sr)
	assert.False(env.hasKey("tx.somevar"))
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, env, rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&stringObject{"abc"}, v)
	assert.Equal(3, cbCalled)
}

func TestRuleEvaluatorSecActionWithIncrement(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1, _ := parseSetVarAction("tx.somevar=123")
	sv2, _ := parseSetVarAction("tx.somevar=+1")
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv1, &sv2}},
	}
	m := make(map[matchKey]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{matches: m, targetsCount: tc}
	env := newEnvMap(sr)
	assert.False(env.hasKey("tx.somevar"))
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, env, rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&integerObject{124}, v)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorMultiTarget1(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "REQUEST_COOKIES"}, {Name: "ARGS"}}, Op: Rx, Val: "abc"},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	m[matchKey{100, 0, Target{Name: "ARGS"}}] = Match{}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, newEnvMap(sr), rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
	assert.Equal(403, code)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorMultiTarget2(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}, {Name: "REQUEST_COOKIES"}}, Op: Rx, Val: "abc"},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	m[matchKey{100, 0, Target{Name: "ARGS"}}] = Match{}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, newEnvMap(sr), rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
	assert.Equal(403, code)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorMultiTargetRunsActionsMultipleTimes(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1, _ := parseSetVarAction("tx.somevar=0")
	sv2, _ := parseSetVarAction("tx.somevar=+1")
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "REQUEST_COOKIES"}, {Name: "ARGS"}}, Op: Rx, Val: "abc"},
					Actions:   []Action{&sv2},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	m[matchKey{200, 0, Target{Name: "REQUEST_COOKIES"}}] = Match{}
	m[matchKey{200, 0, Target{Name: "ARGS"}}] = Match{}
	tc := make(map[Target]int)
	tc[Target{Name: "REQUEST_COOKIES"}] = 1
	tc[Target{Name: "ARGS"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	env := newEnvMap(sr)
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, env, rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&integerObject{2}, v)
	assert.Equal(2, cbCalled)
}

func TestRuleEvaluatorMultiTargetRunsActionsMultipleTimesChained(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1, _ := parseSetVarAction("tx.somevar=0")
	sv2, _ := parseSetVarAction("tx.somevar=+1")
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS", Selector: "a"}, {Name: "ARGS", Selector: "b"}}, Op: Rx, Val: "abc"},
					Actions:   []Action{&sv2},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS", Selector: "c"}, {Name: "ARGS", Selector: "d"}}, Op: Rx, Val: "abc"},
					Actions:   []Action{&sv2},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	m[matchKey{200, 0, Target{Name: "ARGS", Selector: "a"}}] = Match{}
	m[matchKey{200, 0, Target{Name: "ARGS", Selector: "b"}}] = Match{}
	m[matchKey{200, 1, Target{Name: "ARGS", Selector: "c"}}] = Match{}
	m[matchKey{200, 1, Target{Name: "ARGS", Selector: "d"}}] = Match{}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS", Selector: "a"}] = 1
	tc[Target{Name: "ARGS", Selector: "b"}] = 1
	tc[Target{Name: "ARGS", Selector: "c"}] = 1
	tc[Target{Name: "ARGS", Selector: "d"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	env := newEnvMap(sr)
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, env, rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&integerObject{4}, v)
	assert.Equal(2, cbCalled)
}

func TestRuleEvaluatorMultiTargetRunsActionsMultipleTimesChainedNegate(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1, _ := parseSetVarAction("tx.somevar=a")
	sv2, _ := parseSetVarAction("tx.somevar=%{tx.somevar}b")
	sv3, _ := parseSetVarAction("tx.somevar=%{tx.somevar}c")
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS", Selector: "a"}, {Name: "ARGS", Selector: "b"}}, Op: Rx, Val: "abc"},
					Actions:   []Action{&sv2},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS", Selector: "c"}, {Name: "ARGS", Selector: "d"}}, Op: Rx, Val: "abc"},
					Actions:   []Action{&sv3},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	m[matchKey{200, 0, Target{Name: "ARGS", Selector: "a"}}] = Match{}
	m[matchKey{200, 0, Target{Name: "ARGS", Selector: "b"}}] = Match{}
	m[matchKey{200, 1, Target{Name: "ARGS", Selector: "c"}}] = Match{}
	m[matchKey{200, 1, Target{Name: "ARGS", Selector: "d"}}] = Match{}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS", Selector: "a"}] = 1
	tc[Target{Name: "ARGS", Selector: "b"}] = 1
	tc[Target{Name: "ARGS", Selector: "c"}] = 1
	tc[Target{Name: "ARGS", Selector: "d"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	env := newEnvMap(sr)
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, env, rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&stringObject{"abbcc"}, v)
	assert.Equal(cbCalled, 2)
}

func TestRuleEvaluatorNolog(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}, {Name: "REQUEST_COOKIES"}}, Op: Rx, Val: "abc"},
					Actions:   []Action{&NoLogAction{}},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	m[matchKey{100, 0, Target{Name: "ARGS"}}] = Match{}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS"}] = 1
	tc[Target{Name: "REQUEST_COOKIES"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	re.Process(logger, newEnvMap(sr), rules, sr, cb)

	// Assert
	assert.Equal(0, cbCalled)
}

func TestRuleEvaluatorNologOverride(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}, {Name: "REQUEST_COOKIES"}}, Op: Rx, Val: "abc"},
					Actions:   []Action{&NoLogAction{}, &LogAction{}},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	m[matchKey{100, 0, Target{Name: "ARGS"}}] = Match{}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS"}] = 1
	tc[Target{Name: "REQUEST_COOKIES"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	re.Process(logger, newEnvMap(sr), rules, sr, cb)

	// Assert
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorNologChain(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: "abc"},
					Actions:   []Action{},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "REQUEST_COOKIES"}}, Op: Rx, Val: "abc"},
					Actions:   []Action{&NoLogAction{}},
				},
			},
		},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: "abc"},
					Actions:   []Action{&NoLogAction{}},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "REQUEST_COOKIES"}}, Op: Rx, Val: "abc"},
					Actions:   []Action{},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	m[matchKey{100, 0, Target{Name: "ARGS"}}] = Match{}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS"}] = 1
	tc[Target{Name: "REQUEST_COOKIES"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	re.Process(logger, newEnvMap(sr), rules, sr, cb)

	// Assert
	assert.Equal(0, cbCalled)
}

func TestRuleEvaluatorNologNegative(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}, {Name: "REQUEST_COOKIES"}}, Op: Rx, Val: "abc"},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	m[matchKey{100, 0, Target{Name: "ARGS"}}] = Match{}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS"}] = 1
	tc[Target{Name: "REQUEST_COOKIES"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	re.Process(logger, newEnvMap(sr), rules, sr, cb)

	// Assert
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorPhases(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1, _ := parseSetVarAction("tx.somevar=10")
	sv2, _ := parseSetVarAction("tx.somevar=20")
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv1}, Phase: 2},
		&ActionStmt{ID: 200, Actions: []Action{&sv2}, Phase: 1}, // This will run first, because it's phase 1
	}
	m := make(map[matchKey]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{matches: m, targetsCount: tc}
	env := newEnvMap(sr)
	assert.False(env.hasKey("tx.somevar"))
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	re.Process(logger, env, rules, sr, cb)

	// Assert
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&stringObject{"10"}, v)
	assert.Equal(2, cbCalled)
}

func TestRuleEvaluatorDefaultPhase(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1, _ := parseSetVarAction("tx.somevar=10")
	sv2, _ := parseSetVarAction("tx.somevar=20")
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv1}},           // Phase 2 is default
		&ActionStmt{ID: 200, Actions: []Action{&sv2}, Phase: 1}, // This will run first, because it's phase 1
	}
	m := make(map[matchKey]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{matches: m, targetsCount: tc}
	env := newEnvMap(sr)
	assert.False(env.hasKey("tx.somevar"))
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	re.Process(logger, env, rules, sr, cb)

	// Assert
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&stringObject{"10"}, v)
	assert.Equal(2, cbCalled)
}

func TestSkipAfter(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1, _ := parseSetVarAction("tx.somevar=10")
	sv2, _ := parseSetVarAction("tx.somevar=20")
	sv3, _ := parseSetVarAction("tx.othervar=10")
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&SkipAfterAction{Label: "hello1"}, &sv1}},
		&ActionStmt{ID: 200, Actions: []Action{&sv2}},
		&Marker{Label: "hello1"},
		&ActionStmt{ID: 300, Actions: []Action{&sv3}},
	}
	m := make(map[matchKey]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{matches: m, targetsCount: tc}
	env := newEnvMap(sr)
	assert.False(env.hasKey("tx.somevar"))
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	re.Process(logger, env, rules, sr, cb)

	// Assert
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&stringObject{"10"}, v)

	assert.True(env.hasKey("tx.othervar"))
	v, ok = env.get("tx.othervar")
	assert.True(ok)
	assert.Equal(&stringObject{"10"}, v)
	assert.Equal(2, cbCalled)
}

func TestSkipAfterWithinPhase(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1, _ := parseSetVarAction("tx.somevar=10")
	sv2, _ := parseSetVarAction("tx.somevar=20")
	sv3, _ := parseSetVarAction("tx.somevar=30")
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&SkipAfterAction{Label: "hello1"}, &sv1}, Phase: 1},
		&ActionStmt{ID: 200, Actions: []Action{&sv2}, Phase: 2},
		&Marker{Label: "hello1"},
		&ActionStmt{ID: 300, Actions: []Action{&sv3}, Phase: 1},
	}
	m := make(map[matchKey]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{matches: m, targetsCount: tc}
	env := newEnvMap(sr)
	assert.False(env.hasKey("tx.somevar"))
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	re.Process(logger, env, rules, sr, cb)

	// Assert
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&stringObject{"20"}, v)
	assert.Equal(3, cbCalled)
}

func TestMarkerCaseSensitive(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1, _ := parseSetVarAction("tx.somevar=10")
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&SkipAfterAction{Label: "hello1"}}},
		&Marker{Label: "heLLo1"},
		&ActionStmt{ID: 200, Actions: []Action{&sv1}},
	}
	m := make(map[matchKey]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{matches: m, targetsCount: tc}
	env := newEnvMap(sr)
	assert.False(env.hasKey("tx.somevar"))
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	re.Process(logger, env, rules, sr, cb)

	// Assert
	assert.False(env.hasKey("tx.somevar"))
	assert.Equal(1, cbCalled)
}

func TestSkipAfterRunsSetvarAnyway(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1, _ := parseSetVarAction("tx.somevar=10")
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&SkipAfterAction{Label: "hello1"}, &sv1}},
		&Marker{Label: "hello1"},
		&ActionStmt{ID: 200},
	}
	m := make(map[matchKey]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{matches: m, targetsCount: tc}
	env := newEnvMap(sr)
	assert.False(env.hasKey("tx.somevar"))
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	re.Process(logger, env, rules, sr, cb)

	// Assert
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&stringObject{"10"}, v)
	assert.Equal(2, cbCalled)
}

func TestRuleEvaluatorNegate(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: "abc", Neg: true},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	m[matchKey{100, 0, Target{Name: "ARGS"}}] = Match{}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, newEnvMap(sr), rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
	assert.Equal(0, cbCalled)
}

func TestRuleEvaluatorNegateNegative(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: "abc", Neg: true},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, newEnvMap(sr), rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
	assert.Equal(403, code)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorNegateMultiTargets(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS", Selector: "a"}, {Name: "ARGS", Selector: "b"}}, Op: Rx, Val: "abc", Neg: true},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	m[matchKey{100, 0, Target{Name: "ARGS", Selector: "a"}}] = Match{}
	m[matchKey{100, 0, Target{Name: "ARGS", Selector: "b"}}] = Match{}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS", Selector: "a"}] = 1
	tc[Target{Name: "ARGS", Selector: "b"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, newEnvMap(sr), rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
	assert.Equal(0, cbCalled)
}

func TestRuleEvaluatorMultiTargetsFoundNegateNotMatched(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)

	sv1, _ := parseSetVarAction("tx.somevar=0")
	sv2, _ := parseSetVarAction("tx.somevar=+1")
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS", Selector: "a"}, {Name: "ARGS", Selector: "b"}}, Op: Rx, Val: "abc", Neg: true},
					Actions:   []Action{&sv2},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS", Selector: "a"}] = 1
	tc[Target{Name: "ARGS", Selector: "b"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}
	env := newEnvMap(sr)

	// Act
	_, _, err := re.Process(logger, env, rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&integerObject{2}, v)
	assert.Equal(2, cbCalled)
}

func TestRuleEvaluatorMultiTargetsFoundNegateNotMatchedNegative(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)

	sv1, _ := parseSetVarAction("tx.somevar=0")
	sv2, _ := parseSetVarAction("tx.somevar=+1")
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS", Selector: "a"}, {Name: "ARGS", Selector: "b"}}, Op: Rx, Val: "abc", Neg: true},
					Actions:   []Action{&sv2},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS", Selector: "a"}] = 1 // Note ARGS:b not present in this negative test
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}
	env := newEnvMap(sr)

	// Act
	_, _, err := re.Process(logger, env, rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&integerObject{1}, v)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorNegateMultiTxTargets(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "TX", Selector: "abc"}, {Name: "TX", Selector: "def"}}, Op: Rx, Val: "abc", Neg: true},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	m[matchKey{100, 0, Target{Name: "TX", Selector: "abc"}}] = Match{}
	m[matchKey{100, 0, Target{Name: "TX", Selector: "def"}}] = Match{}
	tc := make(map[Target]int)
	tc[Target{Name: "TX", Selector: "abc"}] = 1
	tc[Target{Name: "TX", Selector: "def"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, newEnvMap(sr), rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
	assert.Equal(0, cbCalled)
}

func TestRuleEvaluatorNegateMultiTargetsNegative(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}, {Name: "ARGS_NAMES"}}, Op: Rx, Val: "abc", Neg: true},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	m[matchKey{100, 0, Target{Name: "ARGS"}}] = Match{}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS"}] = 1 // Note: only ARGS, not ARGS_NAMES in this negative test
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, newEnvMap(sr), rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
	assert.Equal(0, cbCalled)
}

func TestRuleEvaluatorNegateMultiTxTargetsNegative(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "TX", Selector: "abc"}, {Name: "TX", Selector: "def"}}, Op: Rx, Val: "abc", Neg: true},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	m[matchKey{100, 0, Target{Name: "TX", Selector: "abc"}}] = Match{}
	tc := make(map[Target]int)
	tc[Target{Name: "TX", Selector: "abc"}] = 1 // Note: only TX:abc, not TX:def in this negative test
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, newEnvMap(sr), rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
	assert.Equal(0, cbCalled)
}

func TestRuleEvaluatorNegateMultiTargetsMissingTarget1(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS", Selector: "myarg1"}, {Name: "ARGS", Selector: "myarg2"}}, Op: Rx, Val: "abc", Neg: true},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	m[matchKey{100, 0, Target{Name: "ARGS", Selector: "myarg1"}}] = Match{} // Note: only ARGS:myarg1, not ARGS:myarg2 in this
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS", Selector: "myarg1"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, newEnvMap(sr), rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
	assert.Equal(0, cbCalled)
}

func TestRuleEvaluatorNegateMultiTargetsMissingTarget2(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS", Selector: "myarg1"}, {Name: "ARGS", Selector: "myarg2"}}, Op: Rx, Val: "abc", Neg: true},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[matchKey]Match)
	m[matchKey{100, 0, Target{Name: "ARGS", Selector: "myarg2"}}] = Match{} // Note: only ARGS:myarg2, not ARGS:myarg1 in this
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS", Selector: "myarg2"}] = 1
	sr := &ScanResults{matches: m, targetsCount: tc}
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, newEnvMap(sr), rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
	assert.Equal(0, cbCalled)
}

func TestRuleEvaluatorCountArgsTarget(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS", Selector: "hello", IsCount: true}}, Op: Eq, Val: "2"},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	em := newEnvMap(&ScanResults{})
	re := NewRuleEvaluator()
	tc1 := make(map[Target]int)
	tc1[Target{Name: "ARGS", Selector: "hello", IsCount: true}] = 2
	sr1 := &ScanResults{targetsCount: tc1}
	tc2 := make(map[Target]int)
	tc2[Target{Name: "ARGS", Selector: "hello", IsCount: true}] = 1
	sr2 := &ScanResults{targetsCount: tc2}
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision1, code1, err1 := re.Process(logger, em, rules, sr1, cb)
	decision2, code2, err2 := re.Process(logger, em, rules, sr2, cb)

	// Assert
	assert.Nil(err1)
	assert.Nil(err2)
	assert.Equal(waf.Block, decision1)
	assert.Equal(waf.Pass, decision2)
	assert.Equal(403, code1)
	assert.Equal(200, code2)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorCountTxTargetSet(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1, _ := parseSetVarAction("tx.critical_anomaly_score=123")
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "TX", Selector: "critical_anomaly_score", IsCount: true}}, Op: Gt, Val: "0"},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	em := newEnvMap(&ScanResults{})
	re := NewRuleEvaluator()
	tc1 := make(map[Target]int)
	sr1 := &ScanResults{targetsCount: tc1}
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision1, code1, err1 := re.Process(logger, em, rules, sr1, cb)

	// Assert
	assert.Nil(err1)
	assert.Equal(waf.Block, decision1)
	assert.Equal(403, code1)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorCountTxTargetNotSet(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "TX", Selector: "critical_anomaly_score", IsCount: true}}, Op: Gt, Val: "0"},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	em := newEnvMap(&ScanResults{})
	re := NewRuleEvaluator()
	tc1 := make(map[Target]int)
	sr1 := &ScanResults{targetsCount: tc1}
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision1, code1, err1 := re.Process(logger, em, rules, sr1, cb)

	// Assert
	assert.Nil(err1)
	assert.Equal(waf.Pass, decision1)
	assert.Equal(200, code1)
	assert.Equal(0, cbCalled)
}

func TestRuleEvaluatorLateScanTarget(t *testing.T) {
	// This test should always trigger regardless of the input request.
	// Verified that this works in ModSecurity with the following config:
	/*
		SecAction "id:501,nolog,setvar:tx.myvar=hello1234"
		SecRule TX:myvar "@streq hello1234" "id:502,deny"
	*/

	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1, _ := parseSetVarAction("tx.myvar=hello1234")
	rules := []Statement{
		&ActionStmt{ID: 501, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 502,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "TX", Selector: "myvar"}}, Op: Streq, Val: `hello1234`},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	em := newEnvMap(&ScanResults{})
	re := NewRuleEvaluator()

	m := make(map[matchKey]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{targetsCount: tc, matches: m}
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, em, rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
	assert.Equal(403, code)
	assert.Equal(1, cbCalled)

}

func TestRuleEvaluatorLateScanCapturedTarget(t *testing.T) {
	// This test should trigger on ?a=hello1234worlda but not on ?a=hello1111worlda
	// Verified that this works in ModSecurity with the following config:
	/*
		SecRule ARGS "(hello\d+)worlda" "id:101,capture,deny,chain"
			SecRule TX:1 "@streq hello1234worlda" ""
	*/

	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 101,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: `(hello\d+)worlda`},
					Actions:   []Action{&CaptureAction{}, &DenyAction{}},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "TX", Selector: "1"}}, Op: Streq, Val: "hello1234"},
				},
			},
		},
	}
	em := newEnvMap(&ScanResults{})
	re := NewRuleEvaluator()

	m := make(map[matchKey]Match)
	m[matchKey{101, 0, Target{Name: "ARGS"}}] = Match{
		Data:          []byte("hello1234worlda"),
		CaptureGroups: [][]byte{[]byte("hello1234worlda"), []byte("hello1234")},
	}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS"}] = 1
	sr := &ScanResults{targetsCount: tc, matches: m}
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, em, rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
	assert.Equal(403, code)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorLateScanTargetAndValue(t *testing.T) {
	// This test should trigger on ?a=hello1234worldb but not on ?a=hello1111worldb
	// This does not work in ModSecurity. Tried and failed with the following config:
	/*
		SecAction "id:201,nolog,setvar:tx.myvar=h.l.o.2.4"
		SecRule ARGS "(hello\d+)worldb" "id:202,capture,deny,chain"
			SecRule TX:1 "^%{tx.myvar}$" ""
	*/

	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	//	sv1, _ := parseSetVarAction("tx.myvar=h.l.o.2.4")
	sv1, _ := parseSetVarAction("tx.myvar=hello1234")
	val := `^%{tx.myvar}$`
	valMacroMatches := variableMacroRegex.FindAllStringSubmatch(val, -1) // TODO this would not be needed if the val field was a lits of tokens rather than a string
	rules := []Statement{
		&ActionStmt{ID: 201, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 202,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: `(hello\d+)worldb`},
					Actions:   []Action{&CaptureAction{}},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "TX", Selector: "1"}}, Op: Rx, Val: val, valMacroMatches: valMacroMatches},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	em := newEnvMap(&ScanResults{})
	re := NewRuleEvaluator()

	m := make(map[matchKey]Match)
	m[matchKey{202, 0, Target{Name: "ARGS"}}] = Match{
		Data:          []byte("hello1234worldb"),
		CaptureGroups: [][]byte{[]byte("hello1234worldb"), []byte("hello1234")},
	}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS"}] = 1
	sr := &ScanResults{targetsCount: tc, matches: m}
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, em, rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
	assert.Equal(403, code)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorLateScanTargetAndCapturedValue(t *testing.T) {
	// This test should trigger on ?a=hello123world123c but not on ?a=hello123world234c
	// Verified that this works in ModSecurity with the following config:
	/*
		SecRule ARGS "hello(\d+)world(\d+)c" "id:303,capture,deny,chain"
			SecRule TX:1 "^%{tx.2}$" ""
	*/

	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	val := `^%{tx.2}$`
	valMacroMatches := variableMacroRegex.FindAllStringSubmatch(val, -1) // TODO this would not be needed if the val field was a lits of tokens rather than a string
	rules := []Statement{
		&Rule{
			ID: 303,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: `hello(\d+)world(\d+)c`},
					Actions:   []Action{&CaptureAction{}},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "TX", Selector: "1"}}, Op: Rx, Val: val, valMacroMatches: valMacroMatches},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	em := newEnvMap(&ScanResults{})
	re := NewRuleEvaluator()

	m := make(map[matchKey]Match)
	m[matchKey{303, 0, Target{Name: "ARGS"}}] = Match{
		Data: []byte("hello1234world1234c"),
		CaptureGroups: [][]byte{
			[]byte("hello1234world1234c"),
			[]byte("1234"),
			[]byte("1234"),
		},
	}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS"}] = 1
	sr := &ScanResults{targetsCount: tc, matches: m}
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, em, rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
	assert.Equal(403, code)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorLateScanValue(t *testing.T) {
	t.SkipNow() // Skip until we support scanning of request fields with variables on the right side for the two special cases where we need it

	// This test should trigger on ?a=hello1234worldd
	// Verified that this works in ModSecurity with the following config:
	/*
		SecAction "id:401,nolog,setvar:tx.myvar=hello1234"
		SecRule ARGS "%{tx.myvar}worldd" "id:402,deny"
	*/

	// Late-scanning a request field is not supported by Azwaf.
	// TODO write a test that ensures that we get some kind of error if we try this
	// TODO there are some special cases (920430, 911100),  where this is needed, but only for certain fields, so let's just keep these fields in scanresults.
	t.Fail()
}

func TestRuleEvaluatorCapturedNotAcrossRules(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	val := `^%{tx.2}$`
	valMacroMatches := variableMacroRegex.FindAllStringSubmatch(val, -1) // TODO this would not be needed if the val field was a lits of tokens rather than a string
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: `hello(\d+)world(\d+)c`},
					Actions:   []Action{&CaptureAction{}},
				},
			},
		},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "TX", Selector: "1"}}, Op: Rx, Val: val, valMacroMatches: valMacroMatches},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	em := newEnvMap(&ScanResults{})
	re := NewRuleEvaluator()

	m := make(map[matchKey]Match)
	m[matchKey{100, 0, Target{Name: "ARGS"}}] = Match{
		Data: []byte("hello1234world1234c"),
		CaptureGroups: [][]byte{
			[]byte("hello1234world1234c"),
			[]byte("1234"),
			[]byte("1234"),
		},
	}
	tc := make(map[Target]int)
	tc[Target{Name: "ARGS"}] = 1
	sr := &ScanResults{targetsCount: tc, matches: m}
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, em, rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorCtlAction(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	c1, _ := parseCtlAction("forceRequestBodyVariable=On")
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&c1}},
	}
	m := make(map[matchKey]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{matches: m, targetsCount: tc}
	env := newEnvMap(sr)
	assert.False(env.hasKey("forceRequestBodyVariable"))
	re := NewRuleEvaluator()
	var cbCalled int
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled++
	}

	// Act
	decision, code, err := re.Process(logger, env, rules, sr, cb)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
	assert.True(env.hasKey("forceRequestBodyVariable"))
	v, ok := env.get("forceRequestBodyVariable")
	assert.True(ok)
	assert.Equal(&stringObject{"On"}, v)
	assert.Equal(1, cbCalled)
}
