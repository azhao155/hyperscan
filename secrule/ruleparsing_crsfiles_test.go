package secrule

import (
	"io/ioutil"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Integration tests that load the actual CRS rule files from the file system.

func TestCrs30(t *testing.T) {
	// Arrange
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(filename), "rulesetfiles/crs3.0/")
	type testrulefile struct {
		filename           string
		expectedChainCount int
	}
	testrulefiles := []testrulefile{
		testrulefile{"crs-setup.appgw.conf", 0},
		testrulefile{"rules/REQUEST-901-INITIALIZATION.conf", 27},
		testrulefile{"rules/REQUEST-903.9001-DRUPAL-EXCLUSION-RULES.conf", 25},
		testrulefile{"rules/REQUEST-903.9002-WORDPRESS-EXCLUSION-RULES.conf", 25},
		testrulefile{"rules/REQUEST-905-COMMON-EXCEPTIONS.conf", 2},
		testrulefile{"rules/REQUEST-910-IP-REPUTATION.conf", 17},
		testrulefile{"rules/REQUEST-911-METHOD-ENFORCEMENT.conf", 9},
		testrulefile{"rules/REQUEST-912-DOS-PROTECTION.conf", 18},
		testrulefile{"rules/REQUEST-913-SCANNER-DETECTION.conf", 13},
		testrulefile{"rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf", 50},
		testrulefile{"rules/REQUEST-921-PROTOCOL-ATTACK.conf", 18},
		testrulefile{"rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf", 12},
		testrulefile{"rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf", 12},
		testrulefile{"rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf", 19},
		testrulefile{"rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf", 21},
		testrulefile{"rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf", 34},
		testrulefile{"rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf", 49},
		testrulefile{"rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf", 11},
		testrulefile{"rules/REQUEST-949-BLOCKING-EVALUATION.conf", 10},
	}
	p := NewRuleParser()

	// Act and assert
	for _, trf := range testrulefiles {
		b, err := ioutil.ReadFile(filepath.Join(dir, trf.filename))
		if err != nil {
			t.Fatalf("Failed to load rule file: %s", err)
		}

		rr, err := p.Parse(string(b))

		if err != nil {
			t.Fatalf("Got unexpected error while loading rule file: %s. Error: %s", trf.filename, err)
		}

		if len(rr) != trf.expectedChainCount {
			ids := []string{}
			for _, r := range rr {
				ids = append(ids, strconv.Itoa(r.ID))
			}

			t.Fatalf("Wrong rule chains count in filename: %s. Actual: %d. Expected: %d. Actual IDs: %s.",
				trf.filename, len(rr), trf.expectedChainCount, strings.Join(ids, ","))
		}
	}
}

func TestCrs229(t *testing.T) {
	// Arrange
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(filename), "rulesetfiles/crs2.2.9/")
	type testrulefile struct {
		filename           string
		expectedChainCount int
	}
	testrulefiles := []testrulefile{
		testrulefile{"modsecurity_crs_10_setup.appgw.conf", 5},
		testrulefile{"base_rules/modsecurity_crs_20_protocol_violations.conf", 23},
		testrulefile{"base_rules/modsecurity_crs_21_protocol_anomalies.conf", 8},
		testrulefile{"base_rules/modsecurity_crs_23_request_limits.conf", 6},
		testrulefile{"base_rules/modsecurity_crs_30_http_policy.conf", 5},
		testrulefile{"base_rules/modsecurity_crs_35_bad_robots.conf", 4},
		testrulefile{"base_rules/modsecurity_crs_40_generic_attacks.conf", 25},
		testrulefile{"base_rules/modsecurity_crs_41_sql_injection_attacks.conf", 55},
		testrulefile{"base_rules/modsecurity_crs_41_xss_attacks.conf", 113},
		testrulefile{"base_rules/modsecurity_crs_42_tight_security.conf", 1},
		testrulefile{"base_rules/modsecurity_crs_45_trojans.conf", 3},
		testrulefile{"base_rules/modsecurity_crs_47_common_exceptions.conf", 3},
		testrulefile{"base_rules/modsecurity_crs_49_inbound_blocking.conf", 2},
		testrulefile{"base_rules/modsecurity_crs_60_correlation.conf", 5},
	}
	p := NewRuleParser()

	// Act and assert
	for _, trf := range testrulefiles {
		b, err := ioutil.ReadFile(filepath.Join(dir, trf.filename))
		if err != nil {
			t.Fatalf("Failed to load rule file: %s", err)
		}

		rr, err := p.Parse(string(b))

		if err != nil {
			t.Fatalf("Got unexpected error while loading rule file: %s. Error: %s", trf.filename, err)
		}

		if len(rr) != trf.expectedChainCount {
			ids := []string{}
			for _, r := range rr {
				ids = append(ids, strconv.Itoa(r.ID))
			}

			t.Fatalf("Wrong rule chains count in filename: %s. Actual: %d. Expected: %d. Actual IDs: %s.",
				trf.filename, len(rr), trf.expectedChainCount, strings.Join(ids, ","))
		}
	}
}
