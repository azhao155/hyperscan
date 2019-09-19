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
	"strconv"
	"strings"
	"testing"
)

type testSuite struct {
	ruleSetID          string
	testRootDir        string
	knownFailures      []string
	paranoiaLevelRules [][]int
}

var testSuites = []testSuite{
	{
		"OWASP CRS 3.0 with config for regression tests",
		"crs3.0/util/regression-tests/tests",
		[]string{"920160-4", "920270-4", "920272-5", "920290-1", "920400-1", "920370-1", "920274-1", "920200-11", "920200-12", "920430-3", "920430-5", "920430-6", "920430-7", "920430-9", "920430-10", "920380-1", "920360-1", "920390-1", "920100-8", "920100-11", "920100-13", "920100-15", "920250-1", "920250-2", "920250-3", "932100-1", "932100-3", "933160-30", "933160-31", "933160-32", "933160-33", "933160-34", "933160-35", "933160-36", "933160-37", "933160-38", "933160-39", "933151-3", "933151-5", "933100-1", "933150-15", "933150-16", "933150-17", "933150-18", "933150-19", "933150-20", "933150-21", "933150-22", "933150-23", "933150-24", "933110-2", "933110-3", "933110-4", "933110-5", "933110-6", "933110-7", "933110-8", "933110-9", "933110-10", "933110-12", "933110-13", "933110-14", "933110-15", "933110-16", "933110-17", "933110-18", "933131-3", "941100-5FN"},
		[][]int{
			[]int{910000, 910100, 910110, 910120, 910130, 910140, 910150, 910160, 910170, 910180, 910190, 911100, 913100, 913110, 913120, 920100, 920120, 920130, 920140, 920160, 920170, 920180, 920190, 920210, 920220, 920240, 920250, 920260, 920270, 920280, 920290, 920310, 920311, 920330, 920340, 920350, 920380, 920360, 920370, 920390, 920400, 920410, 920420, 920430, 920440, 920450, 921100, 921110, 921120, 921130, 921140, 921150, 921160, 930100, 930110, 930120, 930130, 931100, 931110, 931120, 932100, 932105, 932110, 932115, 932120, 932130, 932140, 932150, 932160, 932170, 932171, 933100, 933110, 933120, 933130, 933140, 933150, 933160, 933170, 933180, 941100, 941110, 941120, 941130, 941140, 941150, 941160, 941170, 941180, 941190, 941200, 941210, 941220, 941230, 941240, 941250, 941260, 941270, 941280, 941290, 941300, 941310, 941350, 942100, 942140, 942160, 942170, 942190, 942220, 942230, 942240, 942250, 942270, 942280, 942290, 942320, 942350, 942360, 943100, 943110, 943120},
			[]int{913101, 913102, 920200, 920201, 920230, 920300, 920271, 920320, 921151, 931130, 933151, 941320, 941330, 941340, 942110, 942120, 942130, 942150, 942180, 942200, 942210, 942260, 942300, 942310, 942330, 942340, 942370, 942380, 942390, 942400, 942410, 942430, 942440, 942450},
			[]int{920272, 921170, 921180, 933131, 933161, 933111, 942251, 942420, 942431, 942460},
			[]int{920202, 920273, 920274, 920460, 942421, 942432},
		},
	},
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
	rlfs := secrule.NewRuleLoaderFileSystem()
	rl := secrule.NewCrsRuleLoader(p, rlfs)
	hsfs := hyperscan.NewCacheFileSystem()
	hscache := hyperscan.NewDbCache(hsfs)
	mref := hyperscan.NewMultiRegexEngineFactory(hscache)
	rsf := secrule.NewReqScannerFactory(mref)
	re := secrule.NewRuleEvaluator()
	resLog := &mockResultsLogger{}
	ef := secrule.NewEngineFactory(logger, rl, rsf, re, resLog)
	rbp := bodyparsing.NewRequestBodyParser(testLengthLimits)

	var total, pass, fail, skip int

	results := make(map[string]string)

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
			total++

			if testsToSkip[tc.TestTitle] {
				t.Logf("--- SKIP: %v", tc.TestTitle)
				skip++
				continue
			}

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

		for i, rulesInParanoiaLevel := range ts.paranoiaLevelRules {
			var plPass, plFail, plNotcovered int
			//t.Logf("Paranoia level %v:", i+1)
			for _, id := range rulesInParanoiaLevel {
				v := results[strconv.Itoa(id)]
				if v == "pass" {
					//t.Logf("  %v pass", id)
					plPass++
				} else if v == "fail" {
					//t.Logf("  %v fail", id)
					plFail++
				} else {
					//t.Logf("  %v notCovered", id)
					plNotcovered++
				}
			}
			plTotal := plPass + plFail + plNotcovered
			t.Logf("Paranoia level %d summary: number of rules: %3d, passed: %.2f%%, failed: %.2f%%, not covered: %.2f%%",
				i+1,
				plTotal,
				float32(plPass)/float32(plTotal)*100,
				float32(plFail)/float32(plTotal)*100,
				float32(plNotcovered)/float32(plTotal)*100,
			)
		}
	}

	t.Logf("Total tests: %d, Skip: %d, Pass: %d, Fail: %d", total, skip, pass, fail)
	t.Logf("Total tests pass percent: %d%%", (pass*100)/(pass+fail))

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

func (l *mockResultsLogger) FieldBytesLimitExceeded(request waf.HTTPRequest, limit int) { }
func (l *mockResultsLogger) PausableBytesLimitExceeded(request waf.HTTPRequest, limit int) { }
func (l *mockResultsLogger) TotalBytesLimitExceeded(request waf.HTTPRequest, limit int) { }
func (l *mockResultsLogger) BodyParseError(request waf.HTTPRequest, err error) { }
func (l *mockResultsLogger) SetLogMetaData(metaData waf.ConfigLogMetaData) { }


type mockSecRuleConfig struct {
	ruleSetID string
}

func (c *mockSecRuleConfig) Enabled() bool     { return false }
func (c *mockSecRuleConfig) RuleSetID() string { return c.ruleSetID }
