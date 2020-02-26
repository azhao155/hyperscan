package customrule

import (
	"azwaf/testutils"
	"azwaf/waf"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHyperscanNegationRule(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	//
	// For conditions of 2 variables and 2 values, there are effectively 6 cases
	//     0. both variables match both values (M2M2)
	//     1. one variable matches both values, the other matches only one (M2M1)
	//     2. one variable matches both values, the other matches none (M2M0)
	//     3. both variable matches only one values (M1M1)
	//     4. one variable matches only one values, the other matches none (M1M0)
	//     5. both variable matches none of the values (M0M0)

	hyperscanNegationRule := &mockCustomRule{
		name:     "hyperscanNegationRule",
		priority: 1,
		ruleType: "MatchRule",
		matchConditions: []waf.MatchCondition{
			&mockMatchCondition{
				matchVariables: []waf.MatchVariable{
					&mockMatchVariable{
						variableName: "RequestHeaders",
						selector:     "X-Test-X1",
					},
					&mockMatchVariable{
						variableName: "RequestHeaders",
						selector:     "X-Test-X2",
					},
				},
				operator:        "Contains",
				negateCondition: true,
				matchValues:     []string{"a", "b"},
			},
		},
		action: "Block",
	}

	logEntries := make([]mockResultsLogEntry, 0)

	reqM2M2 := &mockWafHTTPRequest{
		uri: "/", method: "GET", remoteAddr: "127.0.0.1",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Test-X1", v: "abe"},
			&mockHeaderPair{k: "X-Test-X2", v: "bart"},
		},
	}

	reqM2M1 := &mockWafHTTPRequest{
		uri: "/", method: "GET", remoteAddr: "127.0.0.1",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Test-X1", v: "abe"},
			&mockHeaderPair{k: "X-Test-X2", v: "bob"},
		},
	}

	reqM2M0 := &mockWafHTTPRequest{
		uri: "/", method: "GET", remoteAddr: "127.0.0.1",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Test-X1", v: "abe"},
			&mockHeaderPair{k: "X-Test-X2", v: "eve"},
		},
	}

	logEntries = append(logEntries, mockResultsLogEntry{
		ruleID: hyperscanNegationRule.Name(),
		matchedConditions: []waf.ResultsLoggerCustomRulesMatchedConditions{
			waf.ResultsLoggerCustomRulesMatchedConditions{
				ConditionIndex: 0,
				VariableName:   "RequestHeaders",
				FieldName:      "X-Test-X2",
				MatchedValue:   "eve",
			},
		},
	})

	reqM1M1 := &mockWafHTTPRequest{
		uri: "/", method: "GET", remoteAddr: "127.0.0.1",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Test-X1", v: "alice"},
			&mockHeaderPair{k: "X-Test-X2", v: "bob"},
		},
	}

	reqM1M0 := &mockWafHTTPRequest{
		uri: "/", method: "GET", remoteAddr: "127.0.0.1",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Test-X1", v: "alice"},
			&mockHeaderPair{k: "X-Test-X2", v: "eve"},
		},
	}

	logEntries = append(logEntries, mockResultsLogEntry{
		ruleID: hyperscanNegationRule.Name(),
		matchedConditions: []waf.ResultsLoggerCustomRulesMatchedConditions{
			waf.ResultsLoggerCustomRulesMatchedConditions{
				ConditionIndex: 0,
				VariableName:   "RequestHeaders",
				FieldName:      "X-Test-X2",
				MatchedValue:   "eve",
			},
		},
	})

	reqM0M0 := &mockWafHTTPRequest{
		uri: "/", method: "GET", remoteAddr: "127.0.0.1",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Test-X1", v: "chuck"},
			&mockHeaderPair{k: "X-Test-X2", v: "eve"},
		},
	}

	logEntries = append(logEntries, mockResultsLogEntry{
		ruleID: hyperscanNegationRule.Name(),
		matchedConditions: []waf.ResultsLoggerCustomRulesMatchedConditions{
			waf.ResultsLoggerCustomRulesMatchedConditions{
				ConditionIndex: 0,
				VariableName:   "RequestHeaders",
				FieldName:      "X-Test-X1",
				MatchedValue:   "chuck",
			},
		},
	})

	engine, resLog, err := newEngineWithCustomRules(hyperscanNegationRule)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Act
	evalM2M2 := engine.NewEvaluation(logger, resLog, reqM2M2, waf.OtherBody)
	defer evalM2M2.Close()
	errM2M2 := evalM2M2.ScanHeaders()
	decisionM2M2 := evalM2M2.EvalRules()

	evalM2M1 := engine.NewEvaluation(logger, resLog, reqM2M1, waf.OtherBody)
	defer evalM2M1.Close()
	errM2M1 := evalM2M1.ScanHeaders()
	decisionM2M1 := evalM2M1.EvalRules()

	evalM2M0 := engine.NewEvaluation(logger, resLog, reqM2M0, waf.OtherBody)
	defer evalM2M0.Close()
	errM2M0 := evalM2M0.ScanHeaders()
	decisionM2M0 := evalM2M0.EvalRules()

	evalM1M1 := engine.NewEvaluation(logger, resLog, reqM1M1, waf.OtherBody)
	defer evalM1M1.Close()
	errM1M1 := evalM1M1.ScanHeaders()
	decisionM1M1 := evalM1M1.EvalRules()

	evalM1M0 := engine.NewEvaluation(logger, resLog, reqM1M0, waf.OtherBody)
	defer evalM1M0.Close()
	errM1M0 := evalM1M0.ScanHeaders()
	decisionM1M0 := evalM1M0.EvalRules()

	evalM0M0 := engine.NewEvaluation(logger, resLog, reqM0M0, waf.OtherBody)
	defer evalM0M0.Close()
	errM0M0 := evalM0M0.ScanHeaders()
	decisionM0M0 := evalM0M0.EvalRules()

	// Assert
	//
	// Since we are applying the negation on the predicate, same as the
	// implementation on ModSecurity, the truth table for the negated condition
	// is as follows:
	//
	//       | w/o negation | w/ negation
	// ------+--------------+-------------
	//  M2M2 |     TRUE     |    FALSE
	//  M2M1 |     TRUE     |    FALSE
	//  M2M0 |     TRUE     |    TRUE
	//  M1M1 |     TRUE     |    FALSE
	//  M1M0 |     TRUE     |    TRUE
	//  M0M0 |     FALSE    |    TRUE
	//
	// Intuitively, if there exists an M0 in the label, the negated condition
	// should evaluate to TRUE.

	assert.Nil(errM2M2)
	assert.Equal(waf.Pass, decisionM2M2)

	assert.Nil(errM2M1)
	assert.Equal(waf.Pass, decisionM2M1)

	assert.Nil(errM2M0)
	assert.Equal(waf.Block, decisionM2M0)

	assert.Nil(errM1M1)
	assert.Equal(waf.Pass, decisionM1M1)

	assert.Nil(errM1M0)
	assert.Equal(waf.Block, decisionM1M0)

	assert.Nil(errM0M0)
	assert.Equal(waf.Block, decisionM0M0)

	assert.Equal(logEntries, resLog.logEntries)
}

func TestNumericNegationRule(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	//
	// For conditions of 2 variables and 2 values, there are effectively 6 cases
	//     0. both variables match both values (M2M2)
	//     1. one variable matches both values, the other matches only one (M2M1)
	//     2. one variable matches both values, the other matches none (M2M0)
	//     3. both variable matches only one values (M1M1)
	//     4. one variable matches only one values, the other matches none (M1M0)
	//     5. both variable matches none of the values (M0M0)

	numericNegationRule := &mockCustomRule{
		name:     "numericNegationRule",
		priority: 1,
		ruleType: "MatchRule",
		matchConditions: []waf.MatchCondition{
			&mockMatchCondition{
				matchVariables: []waf.MatchVariable{
					&mockMatchVariable{
						variableName: "RequestHeaders",
						selector:     "X-Test-X1",
					},
					&mockMatchVariable{
						variableName: "RequestHeaders",
						selector:     "X-Test-X2",
					},
				},
				operator:        "GreaterThan",
				negateCondition: true,
				matchValues:     []string{"30", "10"},
			},
		},
		action: "Block",
	}

	logEntries := make([]mockResultsLogEntry, 0)

	reqM2M2 := &mockWafHTTPRequest{
		uri: "/", method: "GET", remoteAddr: "127.0.0.1",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Test-X1", v: "40"},
			&mockHeaderPair{k: "X-Test-X2", v: "40"},
		},
	}

	reqM2M1 := &mockWafHTTPRequest{
		uri: "/", method: "GET", remoteAddr: "127.0.0.1",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Test-X1", v: "40"},
			&mockHeaderPair{k: "X-Test-X2", v: "20"},
		},
	}

	reqM2M0 := &mockWafHTTPRequest{
		uri: "/", method: "GET", remoteAddr: "127.0.0.1",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Test-X1", v: "40"},
			&mockHeaderPair{k: "X-Test-X2", v: "0"},
		},
	}

	logEntries = append(logEntries, mockResultsLogEntry{
		ruleID: numericNegationRule.Name(),
		matchedConditions: []waf.ResultsLoggerCustomRulesMatchedConditions{
			waf.ResultsLoggerCustomRulesMatchedConditions{
				ConditionIndex: 0,
				VariableName:   "RequestHeaders",
				FieldName:      "X-Test-X2",
				MatchedValue:   "0",
			},
		},
	})

	reqM1M1 := &mockWafHTTPRequest{
		uri: "/", method: "GET", remoteAddr: "127.0.0.1",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Test-X1", v: "20"},
			&mockHeaderPair{k: "X-Test-X2", v: "20"},
		},
	}

	reqM1M0 := &mockWafHTTPRequest{
		uri: "/", method: "GET", remoteAddr: "127.0.0.1",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Test-X1", v: "20"},
			&mockHeaderPair{k: "X-Test-X2", v: "0"},
		},
	}

	logEntries = append(logEntries, mockResultsLogEntry{
		ruleID: numericNegationRule.Name(),
		matchedConditions: []waf.ResultsLoggerCustomRulesMatchedConditions{
			waf.ResultsLoggerCustomRulesMatchedConditions{
				ConditionIndex: 0,
				VariableName:   "RequestHeaders",
				FieldName:      "X-Test-X2",
				MatchedValue:   "0",
			},
		},
	})

	reqM0M0 := &mockWafHTTPRequest{
		uri: "/", method: "GET", remoteAddr: "127.0.0.1",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Test-X1", v: "0"},
			&mockHeaderPair{k: "X-Test-X2", v: "0"},
		},
	}

	logEntries = append(logEntries, mockResultsLogEntry{
		ruleID: numericNegationRule.Name(),
		matchedConditions: []waf.ResultsLoggerCustomRulesMatchedConditions{
			waf.ResultsLoggerCustomRulesMatchedConditions{
				ConditionIndex: 0,
				VariableName:   "RequestHeaders",
				FieldName:      "X-Test-X1",
				MatchedValue:   "0",
			},
		},
	})

	engine, resLog, err := newEngineWithCustomRules(numericNegationRule)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Act
	evalM2M2 := engine.NewEvaluation(logger, resLog, reqM2M2, waf.OtherBody)
	defer evalM2M2.Close()
	errM2M2 := evalM2M2.ScanHeaders()
	decisionM2M2 := evalM2M2.EvalRules()

	evalM2M1 := engine.NewEvaluation(logger, resLog, reqM2M1, waf.OtherBody)
	defer evalM2M1.Close()
	errM2M1 := evalM2M1.ScanHeaders()
	decisionM2M1 := evalM2M1.EvalRules()

	evalM2M0 := engine.NewEvaluation(logger, resLog, reqM2M0, waf.OtherBody)
	defer evalM2M0.Close()
	errM2M0 := evalM2M0.ScanHeaders()
	decisionM2M0 := evalM2M0.EvalRules()

	evalM1M1 := engine.NewEvaluation(logger, resLog, reqM1M1, waf.OtherBody)
	defer evalM1M1.Close()
	errM1M1 := evalM1M1.ScanHeaders()
	decisionM1M1 := evalM1M1.EvalRules()

	evalM1M0 := engine.NewEvaluation(logger, resLog, reqM1M0, waf.OtherBody)
	defer evalM1M0.Close()
	errM1M0 := evalM1M0.ScanHeaders()
	decisionM1M0 := evalM1M0.EvalRules()

	evalM0M0 := engine.NewEvaluation(logger, resLog, reqM0M0, waf.OtherBody)
	defer evalM0M0.Close()
	errM0M0 := evalM0M0.ScanHeaders()
	decisionM0M0 := evalM0M0.EvalRules()

	// Assert
	//
	// Since we are applying the negation on the predicate, same as the
	// implementation on ModSecurity, the truth table for the negated condition
	// is as follows:
	//
	//       | w/o negation | w/ negation
	// ------+--------------+-------------
	//  M2M2 |     TRUE     |    FALSE
	//  M2M1 |     TRUE     |    FALSE
	//  M2M0 |     TRUE     |    TRUE
	//  M1M1 |     TRUE     |    FALSE
	//  M1M0 |     TRUE     |    TRUE
	//  M0M0 |     FALSE    |    TRUE
	//
	// Intuitively, if there exists an M0 in the label, the negated condition
	// should evaluate to TRUE.

	assert.Nil(errM2M2)
	assert.Equal(waf.Pass, decisionM2M2)

	assert.Nil(errM2M1)
	assert.Equal(waf.Pass, decisionM2M1)

	assert.Nil(errM2M0)
	assert.Equal(waf.Block, decisionM2M0)

	assert.Nil(errM1M1)
	assert.Equal(waf.Pass, decisionM1M1)

	assert.Nil(errM1M0)
	assert.Equal(waf.Block, decisionM1M0)

	assert.Nil(errM0M0)
	assert.Equal(waf.Block, decisionM0M0)

	assert.Equal(logEntries, resLog.logEntries)
}

func TestIPMatchNegationRule(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	//
	// For conditions of 1 variable and 2 values, there are effectively 3 cases
	//     0. the variable matches both values (M2)
	//     1. the variable matches only one value (M1)
	//     2. the variable matches none of the values (M0)

	ipMatchNegationRule := &mockCustomRule{
		name:     "ipMatchNegationRule",
		priority: 1,
		ruleType: "MatchRule",
		matchConditions: []waf.MatchCondition{
			&mockMatchCondition{
				matchVariables: []waf.MatchVariable{
					&mockMatchVariable{
						variableName: "RemoteAddr",
					},
				},
				operator:        "IPMatch",
				negateCondition: true,
				matchValues:     []string{"13.13.0.0/16", "13.13.13.13"},
			},
		},
		action: "Block",
	}

	logEntries := make([]mockResultsLogEntry, 0)

	reqM2 := &mockWafHTTPRequest{uri: "/", method: "GET", remoteAddr: "13.13.13.13"}
	reqM1 := &mockWafHTTPRequest{uri: "/", method: "GET", remoteAddr: "13.13.0.1"}
	reqM0 := &mockWafHTTPRequest{uri: "/", method: "GET", remoteAddr: "127.0.0.1"}

	logEntries = append(logEntries, mockResultsLogEntry{
		ruleID: ipMatchNegationRule.Name(),
		matchedConditions: []waf.ResultsLoggerCustomRulesMatchedConditions{
			waf.ResultsLoggerCustomRulesMatchedConditions{
				ConditionIndex: 0,
				VariableName:   "RemoteAddr",
				MatchedValue:   "127.0.0.1",
			},
		},
	})

	engine, resLog, err := newEngineWithCustomRules(ipMatchNegationRule)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Act
	evalM2 := engine.NewEvaluation(logger, resLog, reqM2, waf.OtherBody)
	defer evalM2.Close()
	errM2 := evalM2.ScanHeaders()
	decisionM2 := evalM2.EvalRules()

	evalM1 := engine.NewEvaluation(logger, resLog, reqM1, waf.OtherBody)
	defer evalM1.Close()
	errM1 := evalM1.ScanHeaders()
	decisionM1 := evalM1.EvalRules()

	evalM0 := engine.NewEvaluation(logger, resLog, reqM0, waf.OtherBody)
	defer evalM0.Close()
	errM0 := evalM0.ScanHeaders()
	decisionM0 := evalM0.EvalRules()

	// Assert
	//
	// Since we are applying the negation on the predicate, same as the
	// implementation on ModSecurity, the truth table for the negated condition
	// is as follows:
	//
	//     | w/o negation | w/ negation
	// ----+--------------+-------------
	//  M2 |     TRUE     |    FALSE
	//  M1 |     TRUE     |    FALSE
	//  M0 |     FALSE    |    TRUE
	//
	// Intuitively, if there exists an M0 in the label, the negated condition
	// should evaluate to TRUE.

	assert.Nil(errM2)
	assert.Equal(waf.Pass, decisionM2)

	assert.Nil(errM1)
	assert.Equal(waf.Pass, decisionM1)

	assert.Nil(errM0)
	assert.Equal(waf.Block, decisionM0)

	assert.Equal(logEntries, resLog.logEntries)
}

func TestGeoMatchNegationRule(t *testing.T) {
	assert := assert.New(t)
	logger := testutils.NewTestLogger(t)

	// Arrange
	//
	// For conditions of 2 variables and 2 values, there are effectively 6 cases
	//     0. RemoteAddr matches one value and X-Forwarded-For header matches both (M1M2)
	//     1. RemoteAddr matches one value and X-Forwarded-For header matches one (M1M1)
	//     2. RemoteAddr matches one value and X-Forwarded-For header matches none (M1M0)
	//     3. RemoteAddr matches none of the values and X-Forwarded-For header matches both (M0M2)
	//     4. RemoteAddr matches none of the values and X-Forwarded-For header matches one (M0M1)
	//     5. Neither RemoteAddr nor X-Forwarded-For header matches any values (M0M0)

	geoMatchNegationRule := &mockCustomRule{
		name:     "geoMatchNegationRule",
		priority: 1,
		ruleType: "MatchRule",
		matchConditions: []waf.MatchCondition{
			&mockMatchCondition{
				matchVariables: []waf.MatchVariable{
					&mockMatchVariable{
						variableName: "RemoteAddr",
					},
					&mockMatchVariable{
						variableName: "RequestHeaders",
						selector:     "X-Forwarded-For",
					},
				},
				operator:        "GeoMatch",
				negateCondition: true,
				matchValues:     []string{"AA", "BB"},
			},
		},
		action: "Block",
	}

	logEntries := make([]mockResultsLogEntry, 0)

	reqM1M2 := &mockWafHTTPRequest{
		uri: "/", method: "GET", remoteAddr: "0.0.0.0",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Forwarded-For", v: "0.0.0.0:8080,1.1.1.1"},
		},
	}

	reqM1M1 := &mockWafHTTPRequest{
		uri: "/", method: "GET", remoteAddr: "0.0.0.0",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Forwarded-For", v: "0.0.0.0:8080,2.2.2.2"},
		},
	}

	reqM1M0 := &mockWafHTTPRequest{
		uri: "/", method: "GET", remoteAddr: "0.0.0.0",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Forwarded-For", v: "2.2.2.2:8080,3.3.3.3"},
		},
	}

	logEntries = append(logEntries, mockResultsLogEntry{
		ruleID: geoMatchNegationRule.Name(),
		matchedConditions: []waf.ResultsLoggerCustomRulesMatchedConditions{
			waf.ResultsLoggerCustomRulesMatchedConditions{
				ConditionIndex: 0,
				VariableName:   "RequestHeaders",
				FieldName:      "X-Forwarded-For",
				MatchedValue:   "2.2.2.2:8080,3.3.3.3",
			},
		},
	})

	reqM0M2 := &mockWafHTTPRequest{
		uri: "/", method: "GET", remoteAddr: "2.2.2.2",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Forwarded-For", v: "0.0.0.0:8080,1.1.1.1"},
		},
	}

	logEntries = append(logEntries, mockResultsLogEntry{
		ruleID: geoMatchNegationRule.Name(),
		matchedConditions: []waf.ResultsLoggerCustomRulesMatchedConditions{
			waf.ResultsLoggerCustomRulesMatchedConditions{
				ConditionIndex: 0,
				VariableName:   "RemoteAddr",
				MatchedValue:   "2.2.2.2",
			},
		},
	})

	reqM0M1 := &mockWafHTTPRequest{
		uri: "/", method: "GET", remoteAddr: "2.2.2.2",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Forwarded-For", v: "1.1.1.1:8080,2.2.2.2"},
		},
	}

	logEntries = append(logEntries, mockResultsLogEntry{
		ruleID: geoMatchNegationRule.Name(),
		matchedConditions: []waf.ResultsLoggerCustomRulesMatchedConditions{
			waf.ResultsLoggerCustomRulesMatchedConditions{
				ConditionIndex: 0,
				VariableName:   "RemoteAddr",
				MatchedValue:   "2.2.2.2",
			},
		},
	})

	reqM0M0 := &mockWafHTTPRequest{
		uri: "/", method: "GET", remoteAddr: "2.2.2.2",
		headers: []waf.HeaderPair{
			&mockHeaderPair{k: "X-Forwarded-For", v: "2.2.2.2:8080,3.3.3.3"},
		},
	}

	logEntries = append(logEntries, mockResultsLogEntry{
		ruleID: geoMatchNegationRule.Name(),
		matchedConditions: []waf.ResultsLoggerCustomRulesMatchedConditions{
			waf.ResultsLoggerCustomRulesMatchedConditions{
				ConditionIndex: 0,
				VariableName:   "RemoteAddr",
				MatchedValue:   "2.2.2.2",
			},
		},
	})

	engine, resLog, err := newEngineWithCustomRules(geoMatchNegationRule)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Act
	evalM1M2 := engine.NewEvaluation(logger, resLog, reqM1M2, waf.OtherBody)
	defer evalM1M2.Close()
	errM1M2 := evalM1M2.ScanHeaders()
	decisionM1M2 := evalM1M2.EvalRules()

	evalM1M1 := engine.NewEvaluation(logger, resLog, reqM1M1, waf.OtherBody)
	defer evalM1M1.Close()
	errM1M1 := evalM1M1.ScanHeaders()
	decisionM1M1 := evalM1M1.EvalRules()

	evalM1M0 := engine.NewEvaluation(logger, resLog, reqM1M0, waf.OtherBody)
	defer evalM1M0.Close()
	errM1M0 := evalM1M0.ScanHeaders()
	decisionM1M0 := evalM1M0.EvalRules()

	evalM0M2 := engine.NewEvaluation(logger, resLog, reqM0M2, waf.OtherBody)
	defer evalM0M2.Close()
	errM0M2 := evalM0M2.ScanHeaders()
	decisionM0M2 := evalM0M2.EvalRules()

	evalM0M1 := engine.NewEvaluation(logger, resLog, reqM0M1, waf.OtherBody)
	defer evalM0M1.Close()
	errM0M1 := evalM0M1.ScanHeaders()
	decisionM0M1 := evalM0M1.EvalRules()

	evalM0M0 := engine.NewEvaluation(logger, resLog, reqM0M0, waf.OtherBody)
	defer evalM0M0.Close()
	errM0M0 := evalM0M0.ScanHeaders()
	decisionM0M0 := evalM0M0.EvalRules()

	// Assert
	//
	// Since we are applying the negation on the predicate, same as the
	// implementation on ModSecurity, the truth table for the negated condition
	// is as follows:
	//
	//       | w/o negation | w/ negation
	// ------+--------------+-------------
	//  M1M2 |     TRUE     |    FALSE
	//  M1M1 |     TRUE     |    FALSE
	//  M1M0 |     TRUE     |    TRUE
	//  M0M2 |     TRUE     |    TRUE
	//  M0M1 |     TRUE     |    TRUE
	//  M0M0 |     FALSE    |    TRUE
	//
	// Intuitively, if there exists an M0 in the label, the negated condition
	// should evaluate to TRUE.

	assert.Nil(errM1M2)
	assert.Equal(waf.Pass, decisionM1M2)

	assert.Nil(errM1M1)
	assert.Equal(waf.Pass, decisionM1M1)

	assert.Nil(errM1M0)
	assert.Equal(waf.Block, decisionM1M0)

	assert.Nil(errM0M2)
	assert.Equal(waf.Block, decisionM0M2)

	assert.Nil(errM0M1)
	assert.Equal(waf.Block, decisionM0M1)

	assert.Nil(errM0M0)
	assert.Equal(waf.Block, decisionM0M0)

	assert.Equal(logEntries, resLog.logEntries)
}
