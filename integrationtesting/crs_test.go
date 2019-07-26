package integrationtesting

import (
	"azwaf/bodyparsing"
	"azwaf/hyperscan"
	"azwaf/secrule"
	"azwaf/testutils"
	"azwaf/waf"
	"flag"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"runtime"
	"testing"
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

var testLengthLimits = waf.LengthLimits{
	MaxLengthField:    1024 * 20,         // 20 KiB
	MaxLengthPausable: 1024 * 128,        // 128 KiB
	MaxLengthTotal:    1024 * 1024 * 700, // 700 MiB
}

func TestCrsRules(t *testing.T) {
	skipRegressionTest(t)

	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)

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
	rbp := bodyparsing.NewRequestBodyParser(testLengthLimits)

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
			ev := e.NewEvaluation(logger, req)
			ev.ScanHeaders()

			err = rbp.Parse(logger, req, func(contentType waf.ContentType, fieldName string, data string) error {
				return ev.ScanBodyField(contentType, fieldName, data)
			})
			if err != nil {
				t.Logf("Error while scanning request body %v", err)
				// TODO some tests expect 400 in this case
			}

			ev.EvalRules()
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
