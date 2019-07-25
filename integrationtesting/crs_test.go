package integrationtesting

import (
	"azwaf/hyperscan"
	"azwaf/secrule"
	"azwaf/waf"
	"azwaf/testutils"
	"flag"
	"github.com/rs/zerolog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"github.com/stretchr/testify/assert"
)

var testRootDir = map[string]string{
	"OWASP CRS 3.0 with config for regression tests": "crs3.0/util/regression-tests/tests",
}

var ruleID = flag.String("ruleID", "", "Rule Id for CRS tests")

func skipRegressionTest(t *testing.T) {
	if os.Getenv("RUN_CRS_REGRESSION_TESTS") == "" {
		t.Skip("Skipping CRS regression test suite")
	}
}

func TestCrsRules(t *testing.T) {
	skipRegressionTest(t)
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)
	// Arrange
	logger = logger.Level(zerolog.ErrorLevel)
	p := secrule.NewRuleParser()
	rl := secrule.NewCrsRuleLoader(p)
	hsfs := hyperscan.NewCacheFileSystem()
	hscache := hyperscan.NewDbCache(hsfs)
	mref := hyperscan.NewMultiRegexEngineFactory(hscache)
	rsf := secrule.NewReqScannerFactory(mref)
	re := secrule.NewRuleEvaluator()
	resLog := &mockResultsLogger{}
	ef := secrule.NewEngineFactory(logger, rl, rsf, re, resLog)

	c := &mockSecRuleConfig{ruleSetID: "OWASP CRS 3.0 with config for regression tests"}
	e, err := ef.NewEngine(c)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	_, thissrcfilename, _, _ := runtime.Caller(0)
	fullPath := filepath.Join(filepath.Dir(thissrcfilename), "../secrule/rulesetfiles", testRootDir[c.RuleSetID()])
	tt, err := GetTests(fullPath, *ruleID)
	if err != nil {
		t.Logf("Error while running tests %v", err)
		return
	}

	var total int
	var pass int
	for _, tc := range tt {
		t.Logf("=== RUN:  %v", tc.TestTitle)
		resLog.ruleMatched = make(map[int]bool)
		for _, req := range tc.Requests {
			// Act
			e.EvalRequest(logger, req)
			//TODO: Add status code check
		}
		total++
		if (tc.MatchExpected && resLog.ruleMatched[tc.ExpectedRuleID]) || (!tc.MatchExpected && !resLog.ruleMatched[tc.ExpectedRuleID]) {
			t.Logf("--- PASS: %v", tc.TestTitle)
			pass++
		} else {
			t.Logf("--- FAIL: %v", tc.TestTitle)
		}
	}

	t.Logf("Total tests: %d, Pass: %d, Fail: %d", total, pass, total-pass)
	t.Logf("Pass %%: %d%%", (pass*100)/total)

	assert.Equal(total, pass)
}

type mockResultsLogger struct {
	ruleMatched map[int]bool
}

func (l *mockResultsLogger) SecRuleTriggered(request waf.HTTPRequest, stmt secrule.Statement, action string, msg string, logData string) {
	r, ok := stmt.(*secrule.Rule)
	if ok {
		l.ruleMatched[r.ID] = true
	}
	return
}

type mockSecRuleConfig struct {
	ruleSetID string
}

func (c *mockSecRuleConfig) ID() string        { return "SecRuleConfig1" }
func (c *mockSecRuleConfig) Enabled() bool     { return false }
func (c *mockSecRuleConfig) RuleSetID() string { return c.ruleSetID }
