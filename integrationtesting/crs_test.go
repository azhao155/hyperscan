package integrationtesting

import (
	sreng "azwaf/secrule/engine"
	srrs "azwaf/secrule/reqscanning"
	srre "azwaf/secrule/ruleevaluation"
	srrp "azwaf/secrule/ruleparsing"

	"azwaf/bodyparsing"
	"azwaf/hyperscan"

	"azwaf/testutils"
	"azwaf/waf"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

type testSuite struct {
	ruleSetID      string
	ruleSetVersion string
	testRootDir    string
	knownFailures  []string
}

var testSuites = []testSuite{
	{
		"OWASP CRS 3.0 with config for regression tests",
		"3.0",
		"crs3.0/util/regression-tests/tests",
		[]string{"920160-4", "920270-4", "920272-5", "920290-1", "920400-1", "920370-1", "920274-1", "920200-11", "920200-12", "920430-3", "920430-5", "920430-6", "920430-7", "920430-9", "920430-10", "920380-1", "920360-1", "920390-1", "920100-8", "920100-11", "920100-13", "920100-15", "920250-1", "920250-2", "920250-3", "932100-1", "932100-3", "933160-30", "933160-31", "933160-32", "933160-33", "933160-34", "933160-35", "933160-36", "933160-37", "933160-38", "933160-39", "933151-3", "933151-5", "933100-1", "933150-15", "933150-16", "933150-17", "933150-18", "933150-19", "933150-20", "933150-21", "933150-22", "933150-23", "933150-24", "933110-2", "933110-3", "933110-4", "933110-5", "933110-6", "933110-7", "933110-8", "933110-9", "933110-10", "933110-12", "933110-13", "933110-14", "933110-15", "933110-16", "933110-17", "933110-18", "933131-3", "941100-5FN"},
	},
	{
		"OWASP CRS 3.1 with config for regression tests",
		"3.1",
		"crs3.1/util/regression-tests/tests",
		[]string{},
	},
	{
		"OWASP CRS 3.2 with config for regression tests",
		"3.2",
		"crs3.2/util/regression-tests/tests",
		[]string{},
	},
}

var ruleID = flag.String("ruleID", "", "Rule Id for CRS tests")
var ruleSetVersion = flag.String("ruleSetVersion", "", "Ruleset Version (e.g. 3.0, 3.1)  for CRS tests")

func skipRegressionTest(t *testing.T) {
	if os.Getenv("RUN_CRS_REGRESSION_TESTS") == "" {
		t.Skip("Skipping CRS regression test suite")
	}
}

func TestCrsRules(t *testing.T) {
	skipRegressionTest(t)

	// Arrange
	logger := testutils.NewTestLogger(t)
	assert := assert.New(t)

	logger = logger.Level(zerolog.ErrorLevel)
	p := srrp.NewRuleParser()
	rlfs := srrp.NewRuleLoaderFileSystem()
	rl := srrp.NewCrsRuleLoader(p, rlfs)
	hsfs := hyperscan.NewCacheFileSystem()
	hscache := hyperscan.NewDbCache(hsfs)
	mref := hyperscan.NewMultiRegexEngineFactory(hscache)
	rsf := srrs.NewReqScannerFactory(mref)
	ref := srre.NewRuleEvaluatorFactory()
	resLog := newMockResultsLogger()
	ef := sreng.NewEngineFactory(logger, rl, rsf, ref)
	rbp := bodyparsing.NewRequestBodyParser(waf.DefaultLengthLimits)
	rlf := &mockResultsLoggerFactory{mockResultsLogger: resLog}

	var total, pass, fail, skip int

	results := make(map[string]string)

	for _, ts := range testSuites {
		if *ruleSetVersion != "" && *ruleSetVersion != ts.ruleSetVersion {
			continue
		}

		c := &mockSecRuleConfig{ruleSetID: ts.ruleSetID}
		e, err := ef.NewEngine(c)
		if err != nil {
			t.Fatalf("Got unexpected error: %s", err)
		}

		wafServer, err := waf.NewStandaloneSecruleServer(logger, rlf, e, rbp)
		if err != nil {
			t.Logf("Error while running tests %v", err)
			return
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
			total++

			if testsToSkip[tc.TestTitle] || tc.Skip {
				t.Logf("--- SKIP: %v", tc.TestTitle)
				skip++
				continue
			}

			resLog.ruleMatched = make(map[int]bool)

			if len(tc.Requests) != 1 {
				panic("len(tc.Requests) != 1")
			}

			for _, req := range tc.Requests {
				if strings.Contains(req.URI(), " ") {
					// If the request line is invalid, the web server would block the request even before it reaches the WAF.
					continue
				}

				var webserverWouldDenyHeader bool
				for _, h := range req.Headers() {
					if strings.ContainsAny(h.Value(), "\r\n") {
						webserverWouldDenyHeader = true
					}
				}
				if webserverWouldDenyHeader {
					// If there was a header that was so invalid that the web server would block the request even before it reaches the WAF.
					continue
				}

				// Act
				_, err = wafServer.EvalRequest(req)
				if err != nil {
					t.Logf("Error while wafServer.EvalRequest(req): %v", err)
					// TODO some tests expect 400 in this case
				}
			}

			ruleid := strings.Split(tc.TestTitle, "-")[0]

			matched := resLog.ruleMatched[tc.ExpectedRuleID]
			if tc.MatchExpected == matched {
				t.Logf("--- PASS: %v", tc.TestTitle)
				pass++

				if results[ruleid] == "" {
					results[ruleid] = "pass"
				}
			} else {
				t.Logf("--- FAIL: %v", tc.TestTitle)
				fail++

				results[ruleid] = "fail"
			}
		}
	}

	t.Logf("Total tests: %d, Skip: %d, Pass: %d, Fail: %d", total, skip, pass, fail)
	t.Logf("Total tests pass percent: %d%%", (pass*100)/(pass+fail))

	assert.Equal(total, pass)
}
