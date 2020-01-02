package ruleevaluation

import (
	. "azwaf/secrule"
	. "azwaf/secrule/ast"

	"azwaf/testutils"
	"azwaf/waf"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRuleEvaluatorNonDisruptiveAction(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	sv := SetVarAction{Variable: Value{StringToken("tx.anomaly_score")}, Operator: Increment, Value: Value{MacroToken{Name: EnvVarTx, Selector: "critical_anomaly_score"}}}
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("something")}},
					Actions:   []Action{sv, &DenyAction{}}, // The predicate will not be satisfied, so this should not run
				},
			},
		},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("ab+c")}},
					Transformations: []Transformation{Lowercase, RemoveWhitespace},
					Actions:         []Action{sv},
				},
			},
		},
	}
	assert := assert.New(t)
	key := MatchKey{200, 0, Target{Name: TargetArgs}}
	m := make(map[MatchKey][]Match)
	m[key] = []Match{{Data: []byte{}}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Pass, decision)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorDisruptiveAction(t *testing.T) {
	logger := testutils.NewTestLogger(t)
	sv := SetVarAction{Variable: Value{StringToken("tx.anomaly_score")}, Operator: Increment, Value: Value{MacroToken{Name: EnvVarTx, Selector: "critical_anomaly_score"}}}
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("ab+c")}},
					Transformations: []Transformation{Lowercase, RemoveWhitespace},
					Actions:         []Action{sv, &DenyAction{}},
				},
			},
		},
	}

	assert := assert.New(t)
	key := MatchKey{100, 0, Target{Name: TargetArgs}}
	m := make(map[MatchKey][]Match)
	m[key] = []Match{{Data: []byte{}}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	decision := re.ProcessPhase(defaultPhase)
	assert.Equal(waf.Block, decision)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorAllowAction(t *testing.T) {
	logger := testutils.NewTestLogger(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("ab+c")}},
					Transformations: []Transformation{Lowercase, RemoveWhitespace},
					Actions:         []Action{&AllowAction{}},
				},
			},
		},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("ab+c")}},
					Transformations: []Transformation{Lowercase, RemoveWhitespace},
					Actions:         []Action{&DenyAction{}},
				},
			},
		},
	}

	assert := assert.New(t)
	key := MatchKey{100, 0, Target{Name: TargetArgs}}
	m := make(map[MatchKey][]Match)
	m[key] = []Match{{Data: []byte{}}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	decision := re.ProcessPhase(defaultPhase)
	assert.Equal(waf.Allow, decision)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorNumericalOperator(t *testing.T) {
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	p := RulePredicate{Targets: []Target{{Name: TargetTx, Selector: "anomaly_score"}}, Op: Ge, Val: Value{MacroToken{Name: EnvVarTx, Selector: "inbound_anomaly_threshold"}}}
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

	em := NewEnvironment(nil)
	em.Set(EnvVarTx, "anomaly_score", Value{IntToken(10)})
	em.Set(EnvVarTx, "inbound_anomaly_threshold", Value{IntToken(5)})
	ref := NewRuleEvaluatorFactory()

	tc := make(map[Target]int)
	sr := &ScanResults{TargetsCount: tc}

	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}

	re := ref.NewRuleEvaluator(logger, em, rules, sr, cb)

	decision := re.ProcessPhase(defaultPhase)
	assert.Equal(waf.Block, decision)
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
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("abc")}},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("def")}},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	m[MatchKey{100, 0, Target{Name: TargetArgs}}] = []Match{{}}
	m[MatchKey{100, 1, Target{Name: TargetArgs}}] = []Match{{}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
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
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("abc")}},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("def")}},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	m[MatchKey{100, 1, Target{Name: TargetArgs}}] = []Match{{}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Pass, decision)
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
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("abc")}},
					Actions:   []Action{&DenyAction{}},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("def")}},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	m[MatchKey{100, 0, Target{Name: TargetArgs}}] = []Match{{}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Pass, decision)
	assert.Equal(0, cbCalled)
}

func TestRuleEvaluatorChainDisruptiveInFirstItemAllItemsRun(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{IntToken(123)}}
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("abc")}},
					Actions:   []Action{&DenyAction{}},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("def")}},
					Actions:   []Action{&sv1},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	m[MatchKey{100, 0, Target{Name: TargetArgs}}] = []Match{{}}
	m[MatchKey{100, 1, Target{Name: TargetArgs}}] = []Match{{}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	env := NewEnvironment(nil)
	assert.Nil(env.Get(EnvVarTx, "somevar"))
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, env, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
	assert.Equal(Value{IntToken(123)}, env.Get(EnvVarTx, "somevar"))
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorChainSetVarInFirstItem(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{IntToken(123)}}
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("abc")}},
					Actions:   []Action{&sv1},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("shouldNotMatch")}},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	m[MatchKey{100, 0, Target{Name: TargetArgs}}] = []Match{{}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	env := NewEnvironment(nil)
	assert.Nil(env.Get(EnvVarTx, "somevar"))
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, env, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Pass, decision)
	assert.Equal(Value{IntToken(123)}, env.Get(EnvVarTx, "somevar"))
	assert.Equal(0, cbCalled)
}

func TestRuleEvaluatorSecAction(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{IntToken(123)}}
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv}},
	}
	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	env := NewEnvironment(nil)
	assert.Nil(env.Get(EnvVarTx, "somevar"))
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, env, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Pass, decision)
	assert.Equal(Value{IntToken(123)}, env.Get(EnvVarTx, "somevar"))
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorSetVarString(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{StringToken("a")}}
	sv2 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{MacroToken{Name: EnvVarTx, Selector: "somevar"}, StringToken("b")}}
	sv3 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{MacroToken{Name: EnvVarTx, Selector: "somevar"}, StringToken("c")}}
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv1}},
		&ActionStmt{ID: 200, Actions: []Action{&sv2}},
		&ActionStmt{ID: 300, Actions: []Action{&sv3}},
	}
	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	env := NewEnvironment(nil)
	assert.Nil(env.Get(EnvVarTx, "somevar"))
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, env, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Pass, decision)
	assert.Equal("abc", env.Get(EnvVarTx, "somevar").String())
	assert.Equal(3, cbCalled)
}

func TestRuleEvaluatorSecActionWithIncrement(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{IntToken(123)}}
	sv2 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Increment, Value: Value{IntToken(1)}}
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv1, &sv2}},
	}
	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	env := NewEnvironment(nil)
	assert.Nil(env.Get(EnvVarTx, "somevar"))
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, env, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Pass, decision)
	assert.Equal(Value{IntToken(124)}, env.Get(EnvVarTx, "somevar"))
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
					Predicate: RulePredicate{Targets: []Target{{Name: TargetRequestCookies}, {Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("abc")}},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	m[MatchKey{100, 0, Target{Name: TargetArgs}}] = []Match{{}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
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
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}, {Name: TargetRequestCookies}}, Op: Rx, Val: Value{StringToken("abc")}},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	m[MatchKey{100, 0, Target{Name: TargetArgs}}] = []Match{{}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorMultiTargetRunsActionsMultipleTimes(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{IntToken(0)}}
	sv2 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Increment, Value: Value{IntToken(1)}}
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetRequestCookies}, {Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("abc")}},
					Actions:   []Action{&sv2},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	m[MatchKey{200, 0, Target{Name: TargetRequestCookies}}] = []Match{{}}
	m[MatchKey{200, 0, Target{Name: TargetArgs}}] = []Match{{}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetRequestCookies}] = 1
	tc[Target{Name: TargetArgs}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	env := NewEnvironment(nil)
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, env, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Pass, decision)
	assert.Equal(Value{IntToken(2)}, env.Get(EnvVarTx, "somevar"))
	assert.Equal(2, cbCalled)
}

func TestRuleEvaluatorMultiTargetRunsActionsMultipleTimesChained(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{IntToken(0)}}
	sv2 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Increment, Value: Value{IntToken(1)}}
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs, Selector: "a"}, {Name: TargetArgs, Selector: "b"}}, Op: Rx, Val: Value{StringToken("abc")}},
					Actions:   []Action{&sv2},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs, Selector: "c"}, {Name: TargetArgs, Selector: "d"}}, Op: Rx, Val: Value{StringToken("abc")}},
					Actions:   []Action{&sv2},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	m[MatchKey{200, 0, Target{Name: TargetArgs, Selector: "a"}}] = []Match{{}}
	m[MatchKey{200, 0, Target{Name: TargetArgs, Selector: "b"}}] = []Match{{}}
	m[MatchKey{200, 1, Target{Name: TargetArgs, Selector: "c"}}] = []Match{{}}
	m[MatchKey{200, 1, Target{Name: TargetArgs, Selector: "d"}}] = []Match{{}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs, Selector: "a"}] = 1
	tc[Target{Name: TargetArgs, Selector: "b"}] = 1
	tc[Target{Name: TargetArgs, Selector: "c"}] = 1
	tc[Target{Name: TargetArgs, Selector: "d"}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	env := NewEnvironment(nil)
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, env, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Pass, decision)
	assert.Equal(Value{IntToken(4)}, env.Get(EnvVarTx, "somevar"))
	assert.Equal(2, cbCalled)
}

func TestRuleEvaluatorMultiTargetRunsActionsMultipleTimesChainedNegate(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{StringToken("a")}}
	sv2 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{MacroToken{Name: EnvVarTx, Selector: "somevar"}, StringToken("b")}}
	sv3 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{MacroToken{Name: EnvVarTx, Selector: "somevar"}, StringToken("c")}}
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs, Selector: "a"}, {Name: TargetArgs, Selector: "b"}}, Op: Rx, Val: Value{StringToken("abc")}},
					Actions:   []Action{&sv2},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs, Selector: "c"}, {Name: TargetArgs, Selector: "d"}}, Op: Rx, Val: Value{StringToken("abc")}},
					Actions:   []Action{&sv3},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	m[MatchKey{200, 0, Target{Name: TargetArgs, Selector: "a"}}] = []Match{{}}
	m[MatchKey{200, 0, Target{Name: TargetArgs, Selector: "b"}}] = []Match{{}}
	m[MatchKey{200, 1, Target{Name: TargetArgs, Selector: "c"}}] = []Match{{}}
	m[MatchKey{200, 1, Target{Name: TargetArgs, Selector: "d"}}] = []Match{{}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs, Selector: "a"}] = 1
	tc[Target{Name: TargetArgs, Selector: "b"}] = 1
	tc[Target{Name: TargetArgs, Selector: "c"}] = 1
	tc[Target{Name: TargetArgs, Selector: "d"}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	env := NewEnvironment(nil)
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, env, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Pass, decision)
	assert.Equal("abbcc", env.Get(EnvVarTx, "somevar").String())
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
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}, {Name: TargetRequestCookies}}, Op: Rx, Val: Value{StringToken("abc")}},
					Actions:   []Action{&NoLogAction{}},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	m[MatchKey{100, 0, Target{Name: TargetArgs}}] = []Match{{}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1
	tc[Target{Name: TargetRequestCookies}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	// Act
	re.ProcessPhase(defaultPhase)

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
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}, {Name: TargetRequestCookies}}, Op: Rx, Val: Value{StringToken("abc")}},
					Actions:   []Action{&NoLogAction{}, &LogAction{}},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	m[MatchKey{100, 0, Target{Name: TargetArgs}}] = []Match{{}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1
	tc[Target{Name: TargetRequestCookies}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	// Act
	re.ProcessPhase(defaultPhase)

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
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("abc")}},
					Actions:   []Action{},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetRequestCookies}}, Op: Rx, Val: Value{StringToken("abc")}},
					Actions:   []Action{&NoLogAction{}},
				},
			},
		},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("abc")}},
					Actions:   []Action{&NoLogAction{}},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetRequestCookies}}, Op: Rx, Val: Value{StringToken("abc")}},
					Actions:   []Action{},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	m[MatchKey{100, 0, Target{Name: TargetArgs}}] = []Match{{}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1
	tc[Target{Name: TargetRequestCookies}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	// Act
	re.ProcessPhase(defaultPhase)

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
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}, {Name: TargetRequestCookies}}, Op: Rx, Val: Value{StringToken("abc")}},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	m[MatchKey{100, 0, Target{Name: TargetArgs}}] = []Match{{}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1
	tc[Target{Name: TargetRequestCookies}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	// Act
	re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorPhases(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{IntToken(10)}}
	sv2 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{IntToken(20)}}
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv1}, Phase: 2},
		&ActionStmt{ID: 200, Actions: []Action{&sv2}, Phase: 1}, // This will run first, because it's phase 1
	}
	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	env := NewEnvironment(nil)
	assert.Nil(env.Get(EnvVarTx, "somevar"))
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, env, rules, sr, cb)

	// Act
	re.ProcessPhase(1)
	re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(Value{IntToken(10)}, env.Get(EnvVarTx, "somevar"))
	assert.Equal(2, cbCalled)
}

func TestRuleEvaluatorDefaultPhase(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{IntToken(10)}}
	sv2 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{IntToken(20)}}
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv1}},           // Phase 2 is default
		&ActionStmt{ID: 200, Actions: []Action{&sv2}, Phase: 1}, // This will run first, because it's phase 1
	}
	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	env := NewEnvironment(nil)
	assert.Nil(env.Get(EnvVarTx, "somevar"))
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, env, rules, sr, cb)

	// Act
	re.ProcessPhase(1)
	re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(Value{IntToken(10)}, env.Get(EnvVarTx, "somevar"))
	assert.Equal(2, cbCalled)
}

func TestSkipAfter(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{IntToken(10)}}
	sv2 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{IntToken(20)}}
	sv3 := SetVarAction{Variable: Value{StringToken("tx.othervar")}, Operator: Set, Value: Value{IntToken(10)}}
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&SkipAfterAction{Label: "hello1"}, &sv1}},
		&ActionStmt{ID: 200, Actions: []Action{&sv2}},
		&Marker{Label: "hello1"},
		&ActionStmt{ID: 300, Actions: []Action{&sv3}},
	}
	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	env := NewEnvironment(nil)
	assert.Nil(env.Get(EnvVarTx, "somevar"))
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, env, rules, sr, cb)

	// Act
	re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(Value{IntToken(10)}, env.Get(EnvVarTx, "somevar"))

	assert.Equal(Value{IntToken(10)}, env.Get(EnvVarTx, "othervar"))
	assert.Equal(2, cbCalled)
}

func TestSkipAfterWithinPhase(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{IntToken(10)}}
	sv2 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{IntToken(20)}}
	sv3 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{IntToken(30)}}
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&SkipAfterAction{Label: "hello1"}, &sv1}, Phase: 1},
		&ActionStmt{ID: 200, Actions: []Action{&sv2}, Phase: 2},
		&Marker{Label: "hello1"},
		&ActionStmt{ID: 300, Actions: []Action{&sv3}, Phase: 1},
	}
	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	env := NewEnvironment(nil)
	assert.Nil(env.Get(EnvVarTx, "somevar"))
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, env, rules, sr, cb)

	// Act
	re.ProcessPhase(1)
	re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(Value{IntToken(20)}, env.Get(EnvVarTx, "somevar"))
	assert.Equal(3, cbCalled)
}

func TestMarkerCaseSensitive(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{IntToken(10)}}
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&SkipAfterAction{Label: "hello1"}}},
		&Marker{Label: "heLLo1"},
		&ActionStmt{ID: 200, Actions: []Action{&sv1}},
	}
	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	env := NewEnvironment(nil)
	assert.Nil(env.Get(EnvVarTx, "somevar"))
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, env, rules, sr, cb)

	// Act
	re.ProcessPhase(defaultPhase)

	// Assert
	assert.Nil(env.Get(EnvVarTx, "somevar"))
	assert.Equal(1, cbCalled)
}

func TestSkipAfterRunsSetvarAnyway(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{IntToken(10)}}
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&SkipAfterAction{Label: "hello1"}, &sv1}},
		&Marker{Label: "hello1"},
		&ActionStmt{ID: 200},
	}
	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	env := NewEnvironment(nil)
	assert.Nil(env.Get(EnvVarTx, "somevar"))
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, env, rules, sr, cb)

	// Act
	re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(Value{IntToken(10)}, env.Get(EnvVarTx, "somevar"))
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
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("abc")}, Neg: true},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	m[MatchKey{100, 0, Target{Name: TargetArgs}}] = []Match{{}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Pass, decision)
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
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("abc")}, Neg: true},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
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
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs, Selector: "a"}, {Name: TargetArgs, Selector: "b"}}, Op: Rx, Val: Value{StringToken("abc")}, Neg: true},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	m[MatchKey{100, 0, Target{Name: TargetArgs, Selector: "a"}}] = []Match{{}}
	m[MatchKey{100, 0, Target{Name: TargetArgs, Selector: "b"}}] = []Match{{}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs, Selector: "a"}] = 1
	tc[Target{Name: TargetArgs, Selector: "b"}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Pass, decision)
	assert.Equal(0, cbCalled)
}

func TestRuleEvaluatorMultiTargetsFoundNegateNotMatched(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)

	sv1 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{IntToken(0)}}
	sv2 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Increment, Value: Value{IntToken(1)}}
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs, Selector: "a"}, {Name: TargetArgs, Selector: "b"}}, Op: Rx, Val: Value{StringToken("abc")}, Neg: true},
					Actions:   []Action{&sv2},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs, Selector: "a"}] = 1
	tc[Target{Name: TargetArgs, Selector: "b"}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	env := NewEnvironment(nil)
	re := ref.NewRuleEvaluator(logger, env, rules, sr, cb)

	// Act
	re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(Value{IntToken(2)}, env.Get(EnvVarTx, "somevar"))
	assert.Equal(2, cbCalled)
}

func TestRuleEvaluatorMultiTargetsFoundNegateNotMatchedNegative(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)

	sv1 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{IntToken(0)}}
	sv2 := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Increment, Value: Value{IntToken(1)}}
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs, Selector: "a"}, {Name: TargetArgs, Selector: "b"}}, Op: Rx, Val: Value{StringToken("abc")}, Neg: true},
					Actions:   []Action{&sv2},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs, Selector: "a"}] = 1 // Note ARGS:b not present in this negative test
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	env := NewEnvironment(nil)
	re := ref.NewRuleEvaluator(logger, env, rules, sr, cb)

	// Act
	re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(Value{IntToken(1)}, env.Get(EnvVarTx, "somevar"))
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
					Predicate: RulePredicate{Targets: []Target{{Name: TargetTx, Selector: "abc"}, {Name: TargetTx, Selector: "def"}}, Op: Rx, Val: Value{StringToken("abc")}, Neg: true},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	m[MatchKey{100, 0, Target{Name: TargetTx, Selector: "abc"}}] = []Match{{}}
	m[MatchKey{100, 0, Target{Name: TargetTx, Selector: "def"}}] = []Match{{}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetTx, Selector: "abc"}] = 1
	tc[Target{Name: TargetTx, Selector: "def"}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Pass, decision)
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
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}, {Name: TargetArgsNames}}, Op: Rx, Val: Value{StringToken("abc")}, Neg: true},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	m[MatchKey{100, 0, Target{Name: TargetArgs}}] = []Match{{}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1 // Note: only ARGS, not ARGS_NAMES in this negative test
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Pass, decision)
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
					Predicate: RulePredicate{Targets: []Target{{Name: TargetTx, Selector: "abc"}, {Name: TargetTx, Selector: "def"}}, Op: Rx, Val: Value{StringToken("abc")}, Neg: true},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	m[MatchKey{100, 0, Target{Name: TargetTx, Selector: "abc"}}] = []Match{{}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetTx, Selector: "abc"}] = 1 // Note: only TX:abc, not TX:def in this negative test
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Pass, decision)
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
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs, Selector: "myarg1"}, {Name: TargetArgs, Selector: "myarg2"}}, Op: Rx, Val: Value{StringToken("abc")}, Neg: true},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	m[MatchKey{100, 0, Target{Name: TargetArgs, Selector: "myarg1"}}] = []Match{{}} // Note: only ARGS:myarg1, not ARGS:myarg2 in this
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs, Selector: "myarg1"}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Pass, decision)
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
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs, Selector: "myarg1"}, {Name: TargetArgs, Selector: "myarg2"}}, Op: Rx, Val: Value{StringToken("abc")}, Neg: true},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	m := make(map[MatchKey][]Match)
	m[MatchKey{100, 0, Target{Name: TargetArgs, Selector: "myarg2"}}] = []Match{{}} // Note: only ARGS:myarg2, not ARGS:myarg1 in this
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs, Selector: "myarg2"}] = 1
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Pass, decision)
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
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs, Selector: "hello", IsCount: true}}, Op: Eq, Val: Value{IntToken(2)}},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	em := NewEnvironment(nil)
	ref := NewRuleEvaluatorFactory()
	tc1 := make(map[Target]int)
	tc1[Target{Name: TargetArgs, Selector: "hello", IsCount: true}] = 2
	sr1 := &ScanResults{TargetsCount: tc1}
	tc2 := make(map[Target]int)
	tc2[Target{Name: TargetArgs, Selector: "hello", IsCount: true}] = 1
	sr2 := &ScanResults{TargetsCount: tc2}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}

	// Act
	re1 := ref.NewRuleEvaluator(logger, em, rules, sr1, cb)
	decision1 := re1.ProcessPhase(defaultPhase)
	re2 := ref.NewRuleEvaluator(logger, em, rules, sr2, cb)
	decision2 := re2.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision1)
	assert.Equal(waf.Pass, decision2)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorCountTxTargetSet(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.critical_anomaly_score")}, Operator: Set, Value: Value{IntToken(123)}}
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetTx, Selector: "critical_anomaly_score", IsCount: true}}, Op: Gt, Val: Value{IntToken(0)}},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	em := NewEnvironment(nil)
	ref := NewRuleEvaluatorFactory()
	tc1 := make(map[Target]int)
	sr1 := &ScanResults{TargetsCount: tc1}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, em, rules, sr1, cb)

	// Act
	decision1 := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision1)
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
					Predicate: RulePredicate{Targets: []Target{{Name: TargetTx, Selector: "critical_anomaly_score", IsCount: true}}, Op: Gt, Val: Value{IntToken(0)}},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	em := NewEnvironment(nil)
	ref := NewRuleEvaluatorFactory()
	tc1 := make(map[Target]int)
	sr1 := &ScanResults{TargetsCount: tc1}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, em, rules, sr1, cb)

	// Act
	decision1 := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Pass, decision1)
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
	sv1 := SetVarAction{Variable: Value{StringToken("tx.myvar")}, Operator: Set, Value: Value{StringToken("hello1234")}}
	rules := []Statement{
		&ActionStmt{ID: 501, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 502,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetTx, Selector: "myvar"}}, Op: Streq, Val: Value{StringToken("hello1234")}},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	em := NewEnvironment(nil)
	ref := NewRuleEvaluatorFactory()

	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{TargetsCount: tc, Matches: m}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, em, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
	assert.Equal(1, cbCalled)

}

func TestRuleEvaluatorLateScanTargetWithTransformation(t *testing.T) {
	// This test should always trigger regardless of the input request.
	// Verified that this works in ModSecurity with the following config:
	/*
		SecAction "id:501,nolog,setvar:tx.myvar=hello1234"
		SecRule TX:myvar "@streq hello1234" "id:502,deny"
	*/

	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.myvar")}, Operator: Set, Value: Value{StringToken("%48E%4cLO1234")}}
	rules := []Statement{
		&ActionStmt{ID: 501, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 502,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: TargetTx, Selector: "myvar"}}, Op: Streq, Val: Value{StringToken("hello1234")}},
					Actions:         []Action{&DenyAction{}},
					Transformations: []Transformation{URLDecode, Lowercase},
				},
			},
		},
	}
	em := NewEnvironment(nil)
	ref := NewRuleEvaluatorFactory()

	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{TargetsCount: tc, Matches: m}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, em, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorLateScanTargetWithTransformationInteger(t *testing.T) {
	// This test should always trigger regardless of the input request.
	// Verified that this works in ModSecurity with the following config:
	/*
		SecAction "id:501,nolog,setvar:tx.myvar=hello1234"
		SecRule TX:myvar "@streq hello1234" "id:502,deny"
	*/

	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.myvar")}, Operator: Set, Value: Value{StringToken("%31%30")}} // url-encoded "10"
	rules := []Statement{
		&ActionStmt{ID: 501, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 502,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: TargetTx, Selector: "myvar"}}, Op: Lt, Val: Value{IntToken(5)}}, // 10 is not less than 5, so this rule should not trigger
					Actions:         []Action{},
					Transformations: []Transformation{URLDecode, Lowercase},
				},
			},
		},
		&Rule{
			ID: 503,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: TargetTx, Selector: "myvar"}}, Op: Lt, Val: Value{IntToken(30)}},
					Actions:         []Action{&DenyAction{}},
					Transformations: []Transformation{URLDecode, Lowercase},
				},
			},
		},
	}
	em := NewEnvironment(nil)
	ref := NewRuleEvaluatorFactory()

	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{TargetsCount: tc, Matches: m}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, em, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
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
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken(`(hello\d+)worlda`)}},
					Actions:   []Action{&CaptureAction{}, &DenyAction{}},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetTx, Selector: "1"}}, Op: Streq, Val: Value{StringToken("hello1234")}},
				},
			},
		},
	}
	em := NewEnvironment(nil)
	ref := NewRuleEvaluatorFactory()

	m := make(map[MatchKey][]Match)
	m[MatchKey{101, 0, Target{Name: TargetArgs}}] = []Match{{
		Data:          []byte("hello1234worlda"),
		CaptureGroups: [][]byte{[]byte("hello1234worlda"), []byte("hello1234")},
	}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1
	sr := &ScanResults{TargetsCount: tc, Matches: m}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, em, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
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
	//	sv1 := parseSetVarAction("tx.myvar=h.l.o.2.4")
	sv1 := SetVarAction{Variable: Value{StringToken("tx.myvar")}, Operator: Set, Value: Value{StringToken("hello1234")}}
	rules := []Statement{
		&ActionStmt{ID: 201, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 202,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken(`(hello\d+)worldb`)}},
					Actions:   []Action{&CaptureAction{}},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetTx, Selector: "1"}}, Op: Rx, Val: Value{StringToken("^"), MacroToken{Name: EnvVarTx, Selector: "myvar"}, StringToken("$")}},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	em := NewEnvironment(nil)
	ref := NewRuleEvaluatorFactory()

	m := make(map[MatchKey][]Match)
	m[MatchKey{202, 0, Target{Name: TargetArgs}}] = []Match{{
		Data:          []byte("hello1234worldb"),
		CaptureGroups: [][]byte{[]byte("hello1234worldb"), []byte("hello1234")},
	}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1
	sr := &ScanResults{TargetsCount: tc, Matches: m}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, em, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
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
	rules := []Statement{
		&Rule{
			ID: 303,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken(`hello(\d+)world(\d+)c`)}},
					Actions:   []Action{&CaptureAction{}},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetTx, Selector: "1"}}, Op: Rx, Val: Value{StringToken("^"), MacroToken{Name: EnvVarTx, Selector: "2"}, StringToken("$")}},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	em := NewEnvironment(nil)
	ref := NewRuleEvaluatorFactory()

	m := make(map[MatchKey][]Match)
	m[MatchKey{303, 0, Target{Name: TargetArgs}}] = []Match{{
		Data: []byte("hello1234world1234c"),
		CaptureGroups: [][]byte{
			[]byte("hello1234world1234c"),
			[]byte("1234"),
			[]byte("1234"),
		},
	}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1
	sr := &ScanResults{TargetsCount: tc, Matches: m}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, em, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorCapturedNotAcrossRules(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken(`hello(\d+)world(\d+)c`)}},
					Actions:   []Action{&CaptureAction{}},
				},
			},
		},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetTx, Selector: "1"}}, Op: Rx, Val: Value{StringToken(`^%{tx.2}$`)}},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	em := NewEnvironment(nil)
	ref := NewRuleEvaluatorFactory()

	m := make(map[MatchKey][]Match)
	m[MatchKey{100, 0, Target{Name: TargetArgs}}] = []Match{{
		Data: []byte("hello1234world1234c"),
		CaptureGroups: [][]byte{
			[]byte("hello1234world1234c"),
			[]byte("1234"),
			[]byte("1234"),
		},
	}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1
	sr := &ScanResults{TargetsCount: tc, Matches: m}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, em, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Pass, decision)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorCtlActionForceRequestBodyScanning(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&CtlAction{Setting: ForceRequestBodyVariable, Value: Value{StringToken("On")}}}},
	}
	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Pass, decision)
	assert.Equal(1, cbCalled)
	assert.Equal(true, re.IsForceRequestBodyScanning())
}

func TestRuleEvaluatorCtlActionForceRequestBodyScanningNegative1(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{&CtlAction{Setting: ForceRequestBodyVariable, Value: Value{StringToken("Off")}}}},
	}
	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Pass, decision)
	assert.Equal(1, cbCalled)
	assert.Equal(false, re.IsForceRequestBodyScanning())
}

func TestRuleEvaluatorCtlActionForceRequestBodyScanningNegative2(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&ActionStmt{ID: 100, Actions: []Action{MsgAction{Msg: Value{StringToken("hello")}}}},
	}
	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	sr := &ScanResults{Matches: m, TargetsCount: tc}
	ref := NewRuleEvaluatorFactory()
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, NewEnvironment(nil), rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Pass, decision)
	assert.Equal(1, cbCalled)
	assert.Equal(false, re.IsForceRequestBodyScanning())
}

func TestRuleEvaluatorMatchedVarRightSide(t *testing.T) {
	// This test should trigger on ?a=helloworld&b=helloworld
	// Verified that this works in ModSecurity with the following config:
	/*
		SecAction "id:101,nolog,setvar:tx.myvar=helloworld"
		SecRule ARGS:a "helloworld" "id:102"
		SecRule TX:MYVAR "@streq %{matched_var}" "id:103,deny"
	*/

	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.MYVAR")}, Operator: Set, Value: Value{StringToken("helloworld")}}
	rules := []Statement{
		&ActionStmt{ID: 101, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 102,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs, Selector: "a"}}, Op: Rx, Val: Value{StringToken("helloworld")}},
				},
			},
		},
		&Rule{
			ID: 103,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetTx, Selector: "myvar"}}, Op: Streq, Val: Value{MacroToken{Name: EnvVarMatchedVar}}},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	em := NewEnvironment(nil)
	ref := NewRuleEvaluatorFactory()

	m := make(map[MatchKey][]Match)
	m[MatchKey{102, 0, Target{Name: TargetArgs, Selector: "a"}}] = []Match{{
		Data:               []byte("helloworld"),
		EntireFieldContent: []byte("helloworld"),
		CaptureGroups: [][]byte{
			[]byte("helloworld"),
		},
	}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs, Selector: "a"}] = 1
	sr := &ScanResults{TargetsCount: tc, Matches: m}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, em, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
	assert.Equal(2, cbCalled)
}

func TestRuleEvaluatorMatchedVarLeftSide(t *testing.T) {
	// This test should trigger on ?a=helloworld1234
	// Verified that this works in ModSecurity with the following config:
	/*
		SecAction "id:101,nolog,setvar:tx.myvar=helloworld"
		SecRule ARGS:a "helloworld1234" "id:102"
		SecRule MATCHED_VAR "@rx ^%{tx.myvar}" "id:103,deny"
	*/

	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.MYVAR")}, Operator: Set, Value: Value{StringToken("helloworld")}}
	rules := []Statement{
		&ActionStmt{ID: 101, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 102,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs, Selector: "a"}}, Op: Rx, Val: Value{StringToken("helloworld1234")}},
				},
			},
		},
		&Rule{
			ID: 103,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetMatchedVar}}, Op: Rx, Val: Value{StringToken("^"), MacroToken{Name: EnvVarTx, Selector: "myvar"}}},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	em := NewEnvironment(nil)
	ref := NewRuleEvaluatorFactory()

	m := make(map[MatchKey][]Match)
	m[MatchKey{102, 0, Target{Name: TargetArgs, Selector: "a"}}] = []Match{{
		Data:               []byte("helloworld1234"),
		EntireFieldContent: []byte("helloworld1234"),
		CaptureGroups: [][]byte{
			[]byte("helloworld1234"),
		},
	}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs, Selector: "a"}] = 1
	sr := &ScanResults{TargetsCount: tc, Matches: m}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, em, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
	assert.Equal(2, cbCalled)
}

func TestRuleEvaluatorMatchedVarLeftSideUpdatesEnv(t *testing.T) {
	// This test should trigger on ?a=helloworld1234
	// Verified that this works in ModSecurity with the following config:
	/*
		SecAction "id:101,nolog,setvar:tx.myvar=helloworld"
		SecRule ARGS:a "helloworld1234" "id:102"
		SecRule MATCHED_VAR "@rx ^%{tx.myvar}" "id:103"
		SecRule MATCHED_VAR "@rx ^%{tx.myvar}" "id:104,deny"
	*/

	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.MYVAR")}, Operator: Set, Value: Value{StringToken("helloworld")}}
	rules := []Statement{
		&ActionStmt{ID: 101, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 102,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs, Selector: "a"}}, Op: Rx, Val: Value{StringToken("helloworld1234")}},
				},
			},
		},
		&Rule{
			ID: 103,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetMatchedVar}}, Op: Rx, Val: Value{StringToken("^"), MacroToken{Name: EnvVarTx, Selector: "myvar"}}},
				},
			},
		},
		&Rule{
			ID: 104,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetMatchedVar}}, Op: Rx, Val: Value{StringToken("^"), MacroToken{Name: EnvVarTx, Selector: "myvar"}}},
					Actions:   []Action{&DenyAction{}},
				},
			},
		}}
	em := NewEnvironment(nil)
	ref := NewRuleEvaluatorFactory()

	m := make(map[MatchKey][]Match)
	m[MatchKey{102, 0, Target{Name: TargetArgs, Selector: "a"}}] = []Match{{
		Data:               []byte("helloworld1234"),
		EntireFieldContent: []byte("helloworld1234"),
		CaptureGroups: [][]byte{
			[]byte("helloworld1234"),
		},
	}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs, Selector: "a"}] = 1
	sr := &ScanResults{TargetsCount: tc, Matches: m}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, em, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
	assert.Equal(3, cbCalled)
}

func TestRuleEvaluatorMatchedVarNameLeftSide(t *testing.T) {
	// This test should trigger on ?helloworld1234=something
	// Verified that this works in ModSecurity with the following config:
	/*
		SecAction "id:101,nolog,setvar:tx.myvar=ARGS:helloworld"
		SecRule ARGS "something" "id:102,chain,deny"
			SecRule MATCHED_VAR_NAME "@rx ^ARGS:helloworld"
	*/

	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.myvar")}, Operator: Set, Value: Value{StringToken("ARGS:helloworld")}}
	rules := []Statement{
		&ActionStmt{ID: 101, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 102,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("something")}},
					Actions:   []Action{&DenyAction{}},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetMatchedVarName}}, Op: Rx, Val: Value{StringToken("^"), MacroToken{Name: EnvVarTx, Selector: "myvar"}}},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	em := NewEnvironment(nil)
	ref := NewRuleEvaluatorFactory()

	m := make(map[MatchKey][]Match)
	m[MatchKey{102, 0, Target{Name: TargetArgs}}] = []Match{{
		Data:               []byte("something"),
		EntireFieldContent: []byte("something"),
		CaptureGroups: [][]byte{
			[]byte("something"),
		},
		TargetName: TargetArgs,
		FieldName:  []byte("helloworld1234"),
	}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1
	sr := &ScanResults{TargetsCount: tc, Matches: m}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, em, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorMatchedVarNumeric(t *testing.T) {
	// This test should trigger on ?a=x&b=x&c=x
	// Verified that this works in ModSecurity with the following config:
	/*
		SecRule &ARGS "@gt 0" "id:101,setvar:TX.ARGS_COUNT=%{MATCHED_VAR}"
		SecRule TX:ARGS_COUNT "@gt 2" "id:102,deny"
	*/

	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 101,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs, IsCount: true}}, Op: Gt, Val: Value{IntToken(0)}},
					Actions:   []Action{&SetVarAction{Variable: Value{StringToken("tx.args_count")}, Value: Value{MacroToken{Name: EnvVarMatchedVar}}}},
				},
			},
		},
		&Rule{
			ID: 102,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetTx, Selector: "args_count"}}, Op: Gt, Val: Value{IntToken(2)}},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}
	em := NewEnvironment(nil)
	ref := NewRuleEvaluatorFactory()

	m := make(map[MatchKey][]Match)
	m[MatchKey{101, 0, Target{Name: TargetArgs}}] = []Match{{
		Data:               []byte("3"),
		EntireFieldContent: []byte("3"),
		CaptureGroups: [][]byte{
			[]byte("3"),
		},
		TargetName: TargetArgs,
		FieldName:  []byte("abc"),
	}}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs, IsCount: true}] = 3
	sr := &ScanResults{TargetsCount: tc, Matches: m}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, em, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
	assert.Equal(2, cbCalled)
}

func TestRuleEvaluatorMatchedVarsCollection(t *testing.T) {
	// This test should trigger on ?a=helloworld9999&b=helloworld1234&a=helloworld1111
	// Verified that this works in ModSecurity with the following config:
	/*
		SecRule ARGS "helloworld" "id:101,chain,deny"
		SecRule MATCHED_VARS "world123" ""
	*/

	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 101,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("helloworld")}},
					Actions:   []Action{&DenyAction{}},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetMatchedVars}}, Op: Rx, Val: Value{StringToken("world123")}},
				},
			},
		},
	}
	em := NewEnvironment(nil)
	ref := NewRuleEvaluatorFactory()

	m := make(map[MatchKey][]Match)
	m[MatchKey{101, 0, Target{Name: TargetArgs}}] = []Match{
		{
			Data:               []byte("helloworld"),
			EntireFieldContent: []byte("helloworld9999"),
			CaptureGroups: [][]byte{
				[]byte("helloworld"),
			},
		},
		{
			Data:               []byte("helloworld"),
			EntireFieldContent: []byte("helloworld1234"),
			CaptureGroups: [][]byte{
				[]byte("helloworld"),
			},
		},
		{
			Data:               []byte("helloworld"),
			EntireFieldContent: []byte("helloworld1111"),
			CaptureGroups: [][]byte{
				[]byte("helloworld"),
			},
		},
	}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 3
	sr := &ScanResults{TargetsCount: tc, Matches: m}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, em, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorMatchedVarsCollectionPersistThroughEntireChain(t *testing.T) {
	// This test should trigger on ?x=abc123&y=def
	// Verified that this works in ModSecurity with the following config:
	/*
		SecRule ARGS "abc" "id:101,chain,deny"
			SecRule ARGS "def" "chain"
			SecRule MATCHED_VARS "abc123" ""
	*/

	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 101,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("abc")}},
					Actions:   []Action{&DenyAction{}},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("def")}},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetMatchedVars}}, Op: Rx, Val: Value{StringToken("abc123")}},
				},
			},
		},
	}
	em := NewEnvironment(nil)
	ref := NewRuleEvaluatorFactory()

	m := make(map[MatchKey][]Match)
	m[MatchKey{101, 0, Target{Name: TargetArgs}}] = []Match{
		{
			Data:               []byte("abc"),
			EntireFieldContent: []byte("abc123"),
			CaptureGroups: [][]byte{
				[]byte("abc"),
			},
		},
	}
	m[MatchKey{101, 1, Target{Name: TargetArgs}}] = []Match{
		{
			Data:               []byte("def"),
			EntireFieldContent: []byte("def"),
			CaptureGroups: [][]byte{
				[]byte("def"),
			},
		},
	}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 2
	sr := &ScanResults{TargetsCount: tc, Matches: m}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, em, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorMatchedVarsNameCollection(t *testing.T) {
	// This test should trigger on ?helloworld9999=abc&helloworld1234=abc&helloworld1111=abc
	// Verified that this works in ModSecurity with the following config:
	/*
		SecRule ARGS "abc" "id:101,chain,deny"
		    SecRule MATCHED_VARS_NAMES "world123" ""
	*/

	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	rules := []Statement{
		&Rule{
			ID: 101,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetArgs}}, Op: Rx, Val: Value{StringToken("abc")}},
					Actions:   []Action{&DenyAction{}},
				},
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetMatchedVarsNames}}, Op: Rx, Val: Value{StringToken("world123")}},
				},
			},
		},
	}
	em := NewEnvironment(nil)
	ref := NewRuleEvaluatorFactory()

	m := make(map[MatchKey][]Match)
	m[MatchKey{101, 0, Target{Name: TargetArgs}}] = []Match{
		{
			FieldName:          []byte("helloworld9999"),
			Data:               []byte("abc"),
			EntireFieldContent: []byte("abc"),
			CaptureGroups: [][]byte{
				[]byte("abc"),
			},
		},
		{
			FieldName:          []byte("helloworld1234"),
			Data:               []byte("abc"),
			EntireFieldContent: []byte("abc"),
			CaptureGroups: [][]byte{
				[]byte("abc"),
			},
		},
		{
			FieldName:          []byte("helloworld1111"),
			Data:               []byte("abc"),
			EntireFieldContent: []byte("abc"),
			CaptureGroups: [][]byte{
				[]byte("abc"),
			},
		},
	}
	tc := make(map[Target]int)
	tc[Target{Name: TargetArgs}] = 1
	sr := &ScanResults{TargetsCount: tc, Matches: m}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	re := ref.NewRuleEvaluator(logger, em, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorLateScanRequestLineRightSide(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.MYVAR")}, Operator: Set, Value: Value{StringToken("helloworld")}}
	rules := []Statement{
		&ActionStmt{ID: 101, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 102,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetRequestLine}}, Op: Rx, Val: Value{MacroToken{Name: EnvVarTx, Selector: "myvar"}}},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}

	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	tc[Target{Name: TargetRequestLine}] = 1
	sr := &ScanResults{TargetsCount: tc, Matches: m}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	em := NewEnvironment(nil)
	em.Set(EnvVarRequestLine, "", Value{StringToken([]byte("GET /a%20bc.php?arg1=helloworld HTTP/1.1"))})
	ref := NewRuleEvaluatorFactory()
	re := ref.NewRuleEvaluator(logger, em, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorLateScanRequestMethodRightSide(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.myvar")}, Operator: Set, Value: Value{StringToken("HELLOWORLDMETHOD")}}
	rules := []Statement{
		&ActionStmt{ID: 101, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 102,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetRequestMethod}}, Op: Rx, Val: Value{MacroToken{Name: EnvVarTx, Selector: "myvar"}}},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}

	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	tc[Target{Name: TargetRequestLine}] = 1
	sr := &ScanResults{TargetsCount: tc, Matches: m}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	em := NewEnvironment(nil)
	em.Set(EnvVarRequestMethod, "", Value{StringToken([]byte("HELLOWORLDMETHOD"))})
	ref := NewRuleEvaluatorFactory()
	re := ref.NewRuleEvaluator(logger, em, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorLateScanRequestProtocolRightSide(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.myvar")}, Operator: Set, Value: Value{StringToken("HTTP/1.1")}}
	rules := []Statement{
		&ActionStmt{ID: 101, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 102,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetRequestProtocol}}, Op: Rx, Val: Value{MacroToken{Name: EnvVarTx, Selector: "myvar"}}},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}

	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	tc[Target{Name: TargetRequestLine}] = 1
	sr := &ScanResults{TargetsCount: tc, Matches: m}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	em := NewEnvironment(nil)
	em.Set(EnvVarRequestProtocol, "", Value{StringToken([]byte("HTTP/1.1"))})
	ref := NewRuleEvaluatorFactory()
	re := ref.NewRuleEvaluator(logger, em, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorLateScanHostHeaderRightSide(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.myvar")}, Operator: Set, Value: Value{StringToken("example.com")}}
	rules := []Statement{
		&ActionStmt{ID: 101, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 102,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetRequestHeaders, Selector: "host"}}, Op: Rx, Val: Value{MacroToken{Name: EnvVarTx, Selector: "myvar"}}},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}

	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	tc[Target{Name: TargetRequestLine}] = 1
	sr := &ScanResults{TargetsCount: tc, Matches: m}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	em := NewEnvironment(nil)
	em.Set(EnvVarRequestHeaders, "host", Value{StringToken([]byte("example.com"))})
	ref := NewRuleEvaluatorFactory()
	re := ref.NewRuleEvaluator(logger, em, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
	assert.Equal(1, cbCalled)
}

func TestRuleEvaluatorTxVarRegexSelector(t *testing.T) {
	/*
		SecAction "id:101,nolog,setvar:tx.my123var=helloworld"
		SecRule TX:/my[0-9]*var/ "@streq helloworld" "id:102,deny"
	*/

	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	sv1 := SetVarAction{Variable: Value{StringToken("tx.my123var")}, Operator: Set, Value: Value{StringToken("helloworld")}}
	rules := []Statement{
		&ActionStmt{ID: 101, Actions: []Action{&sv1, &NoLogAction{}}},
		&Rule{
			ID: 102,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: TargetTx, Selector: "my[0-9]*var", IsRegexSelector: true}}, Op: Eq, Val: Value{StringToken("helloworld")}},
					Actions:   []Action{&DenyAction{}},
				},
			},
		},
	}

	m := make(map[MatchKey][]Match)
	tc := make(map[Target]int)
	tc[Target{Name: TargetRequestLine}] = 1
	sr := &ScanResults{TargetsCount: tc, Matches: m}
	var cbCalled int
	cb := func(stmt Statement, decision waf.Decision, msg string, logData string) {
		cbCalled++
	}
	rxs, err := GetTxTargetRegexSelectorsCompiled(rules)
	assert.Nil(err)
	em := NewEnvironment(rxs)
	ref := NewRuleEvaluatorFactory()
	re := ref.NewRuleEvaluator(logger, em, rules, sr, cb)

	// Act
	decision := re.ProcessPhase(defaultPhase)

	// Assert
	assert.Equal(waf.Block, decision)
	assert.Equal(1, cbCalled)
}
