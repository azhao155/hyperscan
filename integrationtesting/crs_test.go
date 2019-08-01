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

type testSuite struct {
	ruleSetID     string
	testRootDir   string
	knownFailures []string
}

var testSuites = []testSuite{
	{"OWASP CRS 3.0 with config for regression tests", "crs3.0/util/regression-tests/tests", []string{"920160-4", "920270-4", "920272-5", "920290-1", "920400-1", "920370-1", "920274-1", "920200-11", "920200-12", "920430-3", "920430-5", "920430-6", "920430-7", "920430-9", "920430-10", "920380-1", "920360-1", "920390-1", "920100-8", "920100-11", "920100-13", "920100-15", "920250-1", "920250-2", "920250-3", "932100-1", "932100-3", "933160-30", "933160-31", "933160-32", "933160-33", "933160-34", "933160-35", "933160-36", "933160-37", "933160-38", "933160-39", "933151-3", "933151-5", "933100-1", "933150-15", "933150-16", "933150-17", "933150-18", "933150-19", "933150-20", "933150-21", "933150-22", "933150-23", "933150-24", "933110-2", "933110-3", "933110-4", "933110-5", "933110-6", "933110-7", "933110-8", "933110-9", "933110-10", "933110-12", "933110-13", "933110-14", "933110-15", "933110-16", "933110-17", "933110-18", "933131-3", "941100-5FN"}},
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

	var total, pass, fail, skip int

	for _, ts := range testSuites {
		c := &mockSecRuleConfig{ruleSetID: ts.ruleSetID}
		e, err := ef.NewEngine(c)
		if err != nil {
			t.Fatalf("Got unexpected error: %s", err)
		}

		_, thissrcfilename, _, _ := runtime.Caller(0)
		fullPath := filepath.Join(filepath.Dir(thissrcfilename), "../secrule/rulesetfiles", ts.testRootDir)
		tt, err := GetTests(fullPath, *ruleID)
		if err != nil {
			t.Logf("Error while running tests %v", err)
			return
		}

		testsToSkip := make(map[string]bool)
		for _, knownFailure := range ts.knownFailures {
			testsToSkip[knownFailure] = true
		}

		for _, tc := range tt {
			t.Logf("=== RUN:  %v", tc.TestTitle)
			total++

			if testsToSkip[tc.TestTitle] {
				t.Logf("--- SKIP: %v", tc.TestTitle)
				skip++
				continue
			}

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

			if (tc.MatchExpected && resLog.ruleMatched[tc.ExpectedRuleID]) || (!tc.MatchExpected && !resLog.ruleMatched[tc.ExpectedRuleID]) {
				t.Logf("--- PASS: %v", tc.TestTitle)
				pass++
			} else {
				t.Logf("--- FAIL: %v", tc.TestTitle)
				fail++
			}
		}
	}

	t.Logf("Total tests: %d, Skip: %d, Pass: %d, Fail: %d", total, skip, pass, fail)
	t.Logf("Pass percent: %d%%", (pass*100)/(pass+fail))

	assert.Equal(total, pass)
}

type mockResultsLogger struct {
	ruleMatched map[int]bool
}

func (l *mockResultsLogger) SecRuleTriggered(request waf.HTTPRequest, stmt secrule.Statement, action string, msg string, logData string) {
	if l.ruleMatched == nil {
		l.ruleMatched = make(map[int]bool)
	}

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
