package ruleparsing

import (
	. "azwaf/secrule/ast"

	"io/ioutil"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Integration tests that load the actual CRS rule files from the file system.

func TestCrs32(t *testing.T) {
	// Arrange
	testrulefiles := []testrulefile{
		{"crs3.2/rules/REQUEST-901-INITIALIZATION.conf", 31},
		{"crs3.2/rules/REQUEST-903.9001-DRUPAL-EXCLUSION-RULES.conf", 23},
		{"crs3.2/rules/REQUEST-903.9002-WORDPRESS-EXCLUSION-RULES.conf", 31},
		{"crs3.2/rules/REQUEST-903.9003-NEXTCLOUD-EXCLUSION-RULES.conf", 23},
		{"crs3.2/rules/REQUEST-903.9004-DOKUWIKI-EXCLUSION-RULES.conf", 11},
		{"crs3.2/rules/REQUEST-903.9005-CPANEL-EXCLUSION-RULES.conf", 3},
		{"crs3.2/rules/REQUEST-905-COMMON-EXCEPTIONS.conf", 2},
		{"crs3.2/rules/REQUEST-910-IP-REPUTATION.conf", 17},
		{"crs3.2/rules/REQUEST-911-METHOD-ENFORCEMENT.conf", 9},
		{"crs3.2/rules/REQUEST-912-DOS-PROTECTION.conf", 19},
		{"crs3.2/rules/REQUEST-913-SCANNER-DETECTION.conf", 13},
		{"crs3.2/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf", 54},
		{"crs3.2/rules/REQUEST-921-PROTOCOL-ATTACK.conf", 17},
		{"crs3.2/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf", 12},
		{"crs3.2/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf", 12},
		{"crs3.2/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf", 22},
		{"crs3.2/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf", 24},
		{"crs3.2/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf", 36},
		{"crs3.2/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf", 54},
		{"crs3.2/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf", 11},
		{"crs3.2/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf", 17},
		{"crs3.2/rules/REQUEST-949-BLOCKING-EVALUATION.conf", 14},
		{"crs3.2/rules/RESPONSE-950-DATA-LEAKAGES.conf", 11},
		{"crs3.2/rules/RESPONSE-951-DATA-LEAKAGES-SQL.conf", 25},
		{"crs3.2/rules/RESPONSE-952-DATA-LEAKAGES-JAVA.conf", 10},
		{"crs3.2/rules/RESPONSE-953-DATA-LEAKAGES-PHP.conf", 11},
		{"crs3.2/rules/RESPONSE-954-DATA-LEAKAGES-IIS.conf", 12},
		{"crs3.2/rules/RESPONSE-959-BLOCKING-EVALUATION.conf", 13},
		{"crs3.2/rules/RESPONSE-980-CORRELATION.conf", 14},
	}

	// Act and assert
	parseAndCompareRuleCounts(t, testrulefiles)
}

func TestCrs31(t *testing.T) {
	// Arrange
	testrulefiles := []testrulefile{
		{"crs3.1/rules/REQUEST-901-INITIALIZATION.conf", 30},
		{"crs3.1/rules/REQUEST-903.9001-DRUPAL-EXCLUSION-RULES.conf", 23},
		{"crs3.1/rules/REQUEST-903.9002-WORDPRESS-EXCLUSION-RULES.conf", 28},
		{"crs3.1/rules/REQUEST-903.9003-NEXTCLOUD-EXCLUSION-RULES.conf", 23},
		{"crs3.1/rules/REQUEST-903.9004-DOKUWIKI-EXCLUSION-RULES.conf", 11},
		{"crs3.1/rules/REQUEST-903.9005-CPANEL-EXCLUSION-RULES.conf", 3},
		{"crs3.1/rules/REQUEST-905-COMMON-EXCEPTIONS.conf", 2},
		{"crs3.1/rules/REQUEST-910-IP-REPUTATION.conf", 17},
		{"crs3.1/rules/REQUEST-911-METHOD-ENFORCEMENT.conf", 9},
		{"crs3.1/rules/REQUEST-912-DOS-PROTECTION.conf", 19},
		{"crs3.1/rules/REQUEST-913-SCANNER-DETECTION.conf", 13},
		{"crs3.1/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf", 55},
		{"crs3.1/rules/REQUEST-921-PROTOCOL-ATTACK.conf", 17},
		{"crs3.1/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf", 12},
		{"crs3.1/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf", 12},
		{"crs3.1/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf", 22},
		{"crs3.1/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf", 22},
		{"crs3.1/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf", 35},
		{"crs3.1/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf", 53},
		{"crs3.1/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf", 11},
		{"crs3.1/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf", 17},
		{"crs3.1/rules/REQUEST-949-BLOCKING-EVALUATION.conf", 14},
	}

	// Act and assert
	parseAndCompareRuleCounts(t, testrulefiles)
}

func TestCrs30(t *testing.T) {
	// Arrange
	testrulefiles := []testrulefile{
		{"crs3.0/crs-setup.appgw.conf", 0},
		{"crs3.0/rules/REQUEST-901-INITIALIZATION.conf", 27},
		{"crs3.0/rules/REQUEST-903.9001-DRUPAL-EXCLUSION-RULES.conf", 25},
		{"crs3.0/rules/REQUEST-903.9002-WORDPRESS-EXCLUSION-RULES.conf", 25},
		{"crs3.0/rules/REQUEST-905-COMMON-EXCEPTIONS.conf", 2},
		{"crs3.0/rules/REQUEST-910-IP-REPUTATION.conf", 17},
		{"crs3.0/rules/REQUEST-911-METHOD-ENFORCEMENT.conf", 9},
		{"crs3.0/rules/REQUEST-912-DOS-PROTECTION.conf", 18},
		{"crs3.0/rules/REQUEST-913-SCANNER-DETECTION.conf", 13},
		{"crs3.0/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf", 50},
		{"crs3.0/rules/REQUEST-921-PROTOCOL-ATTACK.conf", 18},
		{"crs3.0/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf", 12},
		{"crs3.0/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf", 12},
		{"crs3.0/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf", 19},
		{"crs3.0/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf", 21},
		{"crs3.0/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf", 34},
		{"crs3.0/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf", 49},
		{"crs3.0/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf", 11},
		{"crs3.0/rules/REQUEST-949-BLOCKING-EVALUATION.conf", 10},
	}

	// Act and assert
	parseAndCompareRuleCounts(t, testrulefiles)
}

func TestCrs229(t *testing.T) {
	// Arrange
	testrulefiles := []testrulefile{
		{"crs2.2.9/modsecurity_crs_10_setup.appgw.conf", 5},
		{"crs2.2.9/base_rules/modsecurity_crs_20_protocol_violations.conf", 23},
		{"crs2.2.9/base_rules/modsecurity_crs_21_protocol_anomalies.conf", 8},
		{"crs2.2.9/base_rules/modsecurity_crs_23_request_limits.conf", 6},
		{"crs2.2.9/base_rules/modsecurity_crs_30_http_policy.conf", 5},
		{"crs2.2.9/base_rules/modsecurity_crs_35_bad_robots.conf", 4},
		{"crs2.2.9/base_rules/modsecurity_crs_40_generic_attacks.conf", 25},
		{"crs2.2.9/base_rules/modsecurity_crs_41_sql_injection_attacks.conf", 55},
		{"crs2.2.9/base_rules/modsecurity_crs_41_xss_attacks.conf", 113},
		{"crs2.2.9/base_rules/modsecurity_crs_42_tight_security.conf", 1},
		{"crs2.2.9/base_rules/modsecurity_crs_45_trojans.conf", 3},
		{"crs2.2.9/base_rules/modsecurity_crs_47_common_exceptions.conf", 3},
		{"crs2.2.9/base_rules/modsecurity_crs_49_inbound_blocking.conf", 2},
		{"crs2.2.9/base_rules/modsecurity_crs_60_correlation.conf", 5},
	}

	// Act and assert
	parseAndCompareRuleCounts(t, testrulefiles)
}

type testrulefile struct {
	filename           string
	expectedChainCount int
}

func parseAndCompareRuleCounts(t *testing.T, testrulefiles []testrulefile) {
	p := NewRuleParser()

	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(filename), "..", "rulesetfiles/")

	for _, trf := range testrulefiles {
		fullPath := filepath.Join(dir, trf.filename)
		b, err := ioutil.ReadFile(fullPath)
		if err != nil {
			t.Fatalf("Failed to load rule file: %s", err)
		}

		phraseLoaderCb := func(fileName string) ([]string, error) {
			return loadPhraseFile(path.Join(path.Dir(fullPath), fileName))
		}
		rr, err := p.Parse(string(b), phraseLoaderCb, nil)

		if err != nil {
			t.Fatalf("Got unexpected error while loading rule file: %s. Error: %s", trf.filename, err)
		}

		ids := []string{}
		for _, r := range rr {
			switch r := r.(type) {
			case *Rule:
				ids = append(ids, strconv.Itoa(r.ID))
			}
		}

		if len(ids) != trf.expectedChainCount {
			t.Fatalf("Wrong rule chains count in filename: %s. Actual: %d. Expected: %d. Actual IDs: %s.",
				trf.filename, len(rr), trf.expectedChainCount, strings.Join(ids, ","))
		}
	}
}
