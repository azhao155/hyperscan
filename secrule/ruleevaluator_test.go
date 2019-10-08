package secrule

import (
	"azwaf/testutils"
	"azwaf/waf"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRuleEvaluatorNonDisruptiveAction(t *testing.T) {
	logger := testutils.NewTestLogger(t)
	sv, _ := parseSetVarAction("tx.anomaly_score=+%{tx.critical_anomaly_score}")
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "ab+c"},
					Transformations: []Transformation{Lowercase, RemoveWhitespace},
					Actions:         []Action{sv},
				},
			},
		},
	}

	assert := assert.New(t)
	key := rxMatchKey{100, 0, "ARGS"}
	m := make(map[rxMatchKey]RxMatch)
	m[key] = RxMatch{StartPos: 0, EndPos: 10, Data: []byte{}}
	tp := make(map[string]bool)
	tp["ARGS"] = true
	sr := &ScanResults{m, tp}

	re := NewRuleEvaluator()

	decision, code, err := re.Process(logger, newEnvMap(), rules, sr, nil)
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
}

func TestRuleEvaluatorDisruptiveAction(t *testing.T) {
	logger := testutils.NewTestLogger(t)
	sv, _ := parseSetVarAction("tx.anomaly_score=+%{tx.critical_anomaly_score}")
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "ab+c"},
					Transformations: []Transformation{Lowercase, RemoveWhitespace},
					Actions:         []Action{sv, &DenyAction{}},
				},
			},
		},
	}

	assert := assert.New(t)
	key := rxMatchKey{100, 0, "ARGS"}
	m := make(map[rxMatchKey]RxMatch)
	m[key] = RxMatch{StartPos: 0, EndPos: 10, Data: []byte{}}
	tp := make(map[string]bool)
	tp["ARGS"] = true
	sr := &ScanResults{m, tp}
	re := NewRuleEvaluator()

	decision, code, err := re.Process(logger, newEnvMap(), rules, sr, nil)
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
	assert.Equal(403, code)
}

func TestRuleEvaluatorAllowAction(t *testing.T) {
	logger := testutils.NewTestLogger(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "ab+c"},
					Transformations: []Transformation{Lowercase, RemoveWhitespace},
					Actions:         []Action{&AllowAction{}},
				},
			},
		},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "ab+c"},
					Transformations: []Transformation{Lowercase, RemoveWhitespace},
					Actions:         []Action{&DenyAction{}},
				},
			},
		},
	}

	assert := assert.New(t)
	key := rxMatchKey{100, 0, "ARGS"}
	m := make(map[rxMatchKey]RxMatch)
	m[key] = RxMatch{StartPos: 0, EndPos: 10, Data: []byte{}}
	tp := make(map[string]bool)
	tp["ARGS"] = true
	sr := &ScanResults{m, tp}
	re := NewRuleEvaluator()

	decision, code, err := re.Process(logger, newEnvMap(), rules, sr, nil)
	assert.Nil(err)
	assert.Equal(waf.Allow, decision)
	assert.Equal(200, code)
}

func TestRuleEvaluatorNumericalOperator(t *testing.T) {
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	p := RulePredicate{Targets: []string{"TX:ANOMALY_SCORE"}, Op: Ge, Val: "%{tx.inbound_anomaly_threshold}"}
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

	em := newEnvMap()
	em.set("tx.anomaly_score", &integerObject{Value: 10})
	em.set("tx.inbound_anomaly_threshold", &integerObject{Value: 5})
	re := NewRuleEvaluator()

	tp := make(map[string]bool)
	sr := &ScanResults{targetsPresent: tp}

	decision, code, err := re.Process(logger, em, rules, sr, nil)
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
	assert.Equal(403, code)
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
					Predicate: RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "abc"},
				},
				{
					Predicate: RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "def"},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[rxMatchKey]RxMatch)
	m[rxMatchKey{100, 0, "ARGS"}] = RxMatch{}
	m[rxMatchKey{100, 1, "ARGS"}] = RxMatch{}
	tp := make(map[string]bool)
	tp["ARGS"] = true
	sr := &ScanResults{m, tp}
	re := NewRuleEvaluator()

	// Act
	decision, code, err := re.Process(logger, newEnvMap(), rules, sr, nil)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
	assert.Equal(403, code)
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
					Predicate: RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "abc"},
				},
				{
					Predicate: RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "def"},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[rxMatchKey]RxMatch)
	m[rxMatchKey{100, 1, "ARGS"}] = RxMatch{}
	tp := make(map[string]bool)
	tp["ARGS"] = true
	sr := &ScanResults{m, tp}
	re := NewRuleEvaluator()

	// Act
	decision, code, err := re.Process(logger, newEnvMap(), rules, sr, nil)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
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
					Predicate: RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "abc"},
					Actions:   []Action{&DenyAction{}},
				},
				{
					Predicate: RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "def"},
				},
			},
		},
	}
	m := make(map[rxMatchKey]RxMatch)
	m[rxMatchKey{100, 0, "ARGS"}] = RxMatch{}
	tp := make(map[string]bool)
	tp["ARGS"] = true
	sr := &ScanResults{m, tp}
	re := NewRuleEvaluator()

	// Act
	decision, code, err := re.Process(logger, newEnvMap(), rules, sr, nil)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
}

func TestRuleEvaluatorChainDisruptiveInFirstItemAllItemsRunAnyway(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	sv1, _ := parseSetVarAction("tx.somevar=123")
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "abc"},
					Actions:   []Action{&DenyAction{}},
				},
				{
					Predicate: RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "def"},
					Actions:   []Action{&sv1},
				},
			},
		},
	}
	m := make(map[rxMatchKey]RxMatch)
	m[rxMatchKey{100, 0, "ARGS"}] = RxMatch{}
	m[rxMatchKey{100, 1, "ARGS"}] = RxMatch{}
	tp := make(map[string]bool)
	tp["ARGS"] = true
	sr := &ScanResults{m, tp}
	env := newEnvMap()
	assert.False(env.hasKey("tx.somevar"))
	re := NewRuleEvaluator()

	// Act
	decision, code, err := re.Process(logger, env, rules, sr, nil)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&stringObject{"123"}, v)
	assert.Equal(403, code)
}

func TestRuleEvaluatorSecAction(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv, _ := parseSetVarAction("tx.somevar=123")
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv}},
	}
	m := make(map[rxMatchKey]RxMatch)
	tp := make(map[string]bool)
	sr := &ScanResults{m, tp}
	env := newEnvMap()
	assert.False(env.hasKey("tx.somevar"))
	re := NewRuleEvaluator()

	// Act
	decision, code, err := re.Process(logger, env, rules, sr, nil)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&stringObject{"123"}, v)
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
	m := make(map[rxMatchKey]RxMatch)
	tp := make(map[string]bool)
	sr := &ScanResults{m, tp}
	env := newEnvMap()
	assert.False(env.hasKey("tx.somevar"))
	re := NewRuleEvaluator()

	// Act
	decision, code, err := re.Process(logger, env, rules, sr, nil)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&integerObject{124}, v)
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
					Predicate: RulePredicate{Targets: []string{"REQUEST_COOKIES", "ARGS"}, Op: Rx, Val: "abc"},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[rxMatchKey]RxMatch)
	m[rxMatchKey{100, 0, "ARGS"}] = RxMatch{}
	tp := make(map[string]bool)
	tp["ARGS"] = true
	sr := &ScanResults{m, tp}
	re := NewRuleEvaluator()

	// Act
	decision, code, err := re.Process(logger, newEnvMap(), rules, sr, nil)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
	assert.Equal(403, code)
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
					Predicate: RulePredicate{Targets: []string{"ARGS", "REQUEST_COOKIES"}, Op: Rx, Val: "abc"},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[rxMatchKey]RxMatch)
	m[rxMatchKey{100, 0, "ARGS"}] = RxMatch{}
	tp := make(map[string]bool)
	tp["ARGS"] = true
	sr := &ScanResults{m, tp}
	re := NewRuleEvaluator()

	// Act
	decision, code, err := re.Process(logger, newEnvMap(), rules, sr, nil)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
	assert.Equal(403, code)
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
					Predicate: RulePredicate{Targets: []string{"ARGS", "REQUEST_COOKIES"}, Op: Rx, Val: "abc"},
					Actions:   []Action{&NoLogAction{}},
				},
			},
		},
	}
	m := make(map[rxMatchKey]RxMatch)
	m[rxMatchKey{100, 0, "ARGS"}] = RxMatch{}
	tp := make(map[string]bool)
	tp["ARGS"] = true
	tp["REQUEST_COOKIES"] = true
	sr := &ScanResults{m, tp}
	re := NewRuleEvaluator()
	cbCalled := false
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled = true
	}

	// Act
	re.Process(logger, newEnvMap(), rules, sr, cb)

	// Assert
	assert.False(cbCalled)
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
					Predicate: RulePredicate{Targets: []string{"ARGS", "REQUEST_COOKIES"}, Op: Rx, Val: "abc"},
					Actions:   []Action{&NoLogAction{}, &LogAction{}},
				},
			},
		},
	}
	m := make(map[rxMatchKey]RxMatch)
	m[rxMatchKey{100, 0, "ARGS"}] = RxMatch{}
	tp := make(map[string]bool)
	tp["ARGS"] = true
	tp["REQUEST_COOKIES"] = true
	sr := &ScanResults{m, tp}
	re := NewRuleEvaluator()
	cbCalled := false
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled = true
	}

	// Act
	re.Process(logger, newEnvMap(), rules, sr, cb)

	// Assert
	assert.True(cbCalled)
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
					Predicate: RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "abc"},
					Actions:   []Action{},
				},
				{
					Predicate: RulePredicate{Targets: []string{"REQUEST_COOKIES"}, Op: Rx, Val: "abc"},
					Actions:   []Action{&NoLogAction{}},
				},
			},
		},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "abc"},
					Actions:   []Action{&NoLogAction{}},
				},
				{
					Predicate: RulePredicate{Targets: []string{"REQUEST_COOKIES"}, Op: Rx, Val: "abc"},
					Actions:   []Action{},
				},
			},
		},
	}
	m := make(map[rxMatchKey]RxMatch)
	m[rxMatchKey{100, 0, "ARGS"}] = RxMatch{}
	tp := make(map[string]bool)
	tp["ARGS"] = true
	tp["REQUEST_COOKIES"] = true
	sr := &ScanResults{m, tp}
	re := NewRuleEvaluator()
	cbCalled := false
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled = true
	}

	// Act
	re.Process(logger, newEnvMap(), rules, sr, cb)

	// Assert
	assert.False(cbCalled)
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
					Predicate: RulePredicate{Targets: []string{"ARGS", "REQUEST_COOKIES"}, Op: Rx, Val: "abc"},
				},
			},
		},
	}
	m := make(map[rxMatchKey]RxMatch)
	m[rxMatchKey{100, 0, "ARGS"}] = RxMatch{}
	tp := make(map[string]bool)
	tp["ARGS"] = true
	tp["REQUEST_COOKIES"] = true
	sr := &ScanResults{m, tp}
	re := NewRuleEvaluator()
	cbCalled := false
	cb := func(stmt Statement, isDisruptive bool, msg string, logData string) {
		cbCalled = true
	}

	// Act
	re.Process(logger, newEnvMap(), rules, sr, cb)

	// Assert
	assert.True(cbCalled)
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
	m := make(map[rxMatchKey]RxMatch)
	tp := make(map[string]bool)
	sr := &ScanResults{m, tp}
	env := newEnvMap()
	assert.False(env.hasKey("tx.somevar"))
	re := NewRuleEvaluator()

	// Act
	re.Process(logger, env, rules, sr, nil)

	// Assert
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&stringObject{"10"}, v)
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
	m := make(map[rxMatchKey]RxMatch)
	tp := make(map[string]bool)
	sr := &ScanResults{m, tp}
	env := newEnvMap()
	assert.False(env.hasKey("tx.somevar"))
	re := NewRuleEvaluator()

	// Act
	re.Process(logger, env, rules, sr, nil)

	// Assert
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&stringObject{"10"}, v)
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
	m := make(map[rxMatchKey]RxMatch)
	tp := make(map[string]bool)
	sr := &ScanResults{m, tp}
	env := newEnvMap()
	assert.False(env.hasKey("tx.somevar"))
	re := NewRuleEvaluator()

	// Act
	re.Process(logger, env, rules, sr, nil)

	// Assert
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&stringObject{"10"}, v)

	assert.True(env.hasKey("tx.othervar"))
	v, ok = env.get("tx.othervar")
	assert.True(ok)
	assert.Equal(&stringObject{"10"}, v)
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
	m := make(map[rxMatchKey]RxMatch)
	tp := make(map[string]bool)
	sr := &ScanResults{m, tp}
	env := newEnvMap()
	assert.False(env.hasKey("tx.somevar"))
	re := NewRuleEvaluator()

	// Act
	re.Process(logger, env, rules, sr, nil)

	// Assert
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&stringObject{"20"}, v)
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
	m := make(map[rxMatchKey]RxMatch)
	tp := make(map[string]bool)
	sr := &ScanResults{m, tp}
	env := newEnvMap()
	assert.False(env.hasKey("tx.somevar"))
	re := NewRuleEvaluator()

	// Act
	re.Process(logger, env, rules, sr, nil)

	// Assert
	assert.False(env.hasKey("tx.somevar"))
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
	m := make(map[rxMatchKey]RxMatch)
	tp := make(map[string]bool)
	sr := &ScanResults{m, tp}
	env := newEnvMap()
	assert.False(env.hasKey("tx.somevar"))
	re := NewRuleEvaluator()

	// Act
	re.Process(logger, env, rules, sr, nil)

	// Assert
	assert.True(env.hasKey("tx.somevar"))
	v, ok := env.get("tx.somevar")
	assert.True(ok)
	assert.Equal(&stringObject{"10"}, v)
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
					Predicate: RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "abc", Neg: true},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[rxMatchKey]RxMatch)
	m[rxMatchKey{100, 0, "ARGS"}] = RxMatch{}
	tp := make(map[string]bool)
	tp["ARGS"] = true
	sr := &ScanResults{m, tp}
	re := NewRuleEvaluator()

	// Act
	decision, code, err := re.Process(logger, newEnvMap(), rules, sr, nil)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
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
					Predicate: RulePredicate{Targets: []string{"ARGS"}, Op: Rx, Val: "abc", Neg: true},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[rxMatchKey]RxMatch)
	tp := make(map[string]bool)
	tp["ARGS"] = true
	sr := &ScanResults{m, tp}
	re := NewRuleEvaluator()

	// Act
	decision, code, err := re.Process(logger, newEnvMap(), rules, sr, nil)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Block, decision)
	assert.Equal(403, code)
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
					Predicate: RulePredicate{Targets: []string{"ARGS", "ARGS_NAMES"}, Op: Rx, Val: "abc", Neg: true},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[rxMatchKey]RxMatch)
	m[rxMatchKey{100, 0, "ARGS"}] = RxMatch{}
	m[rxMatchKey{100, 0, "ARGS_NAMES"}] = RxMatch{}
	tp := make(map[string]bool)
	tp["ARGS"] = true
	tp["ARGS_NAMES"] = true
	sr := &ScanResults{m, tp}
	re := NewRuleEvaluator()

	// Act
	decision, code, err := re.Process(logger, newEnvMap(), rules, sr, nil)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
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
					Predicate: RulePredicate{Targets: []string{"ARGS", "ARGS_NAMES"}, Op: Rx, Val: "abc", Neg: true},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[rxMatchKey]RxMatch)
	m[rxMatchKey{100, 0, "ARGS"}] = RxMatch{}
	m[rxMatchKey{100, 0, "ARGS_NAMES"}] = RxMatch{}
	tp := make(map[string]bool)
	tp["ARGS"] = true // Note: only ARGS, not ARGS_NAMES in this negative test
	sr := &ScanResults{m, tp}
	re := NewRuleEvaluator()

	// Act
	decision, code, err := re.Process(logger, newEnvMap(), rules, sr, nil)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
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
					Predicate: RulePredicate{Targets: []string{"ARGS:myarg1", "ARGS:myarg2"}, Op: Rx, Val: "abc", Neg: true},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[rxMatchKey]RxMatch)
	m[rxMatchKey{100, 0, "ARGS:myarg1"}] = RxMatch{} // Note: only ARGS:myarg1, not ARGS:myarg2 in this
	tp := make(map[string]bool)
	tp["ARGS:myarg1"] = true
	sr := &ScanResults{m, tp}
	re := NewRuleEvaluator()

	// Act
	decision, code, err := re.Process(logger, newEnvMap(), rules, sr, nil)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
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
					Predicate: RulePredicate{Targets: []string{"ARGS:myarg1", "ARGS:myarg2"}, Op: Rx, Val: "abc", Neg: true},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[rxMatchKey]RxMatch)
	m[rxMatchKey{100, 0, "ARGS:myarg2"}] = RxMatch{} // Note: only ARGS:myarg2, not ARGS:myarg1 in this
	tp := make(map[string]bool)
	tp["ARGS:myarg2"] = true
	sr := &ScanResults{m, tp}
	re := NewRuleEvaluator()

	// Act
	decision, code, err := re.Process(logger, newEnvMap(), rules, sr, nil)

	// Assert
	assert.Nil(err)
	assert.Equal(waf.Pass, decision)
	assert.Equal(200, code)
}
