package secrule

import (
	"azwaf/waf"
	"fmt"
	"github.com/rs/zerolog/log"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// RuleLoader obtains rules for a given rule set.
type RuleLoader interface {
	Rules(r waf.RuleSetID) (statements []Statement, err error)
}

type crsRuleLoader struct {
	parser RuleParser
}

// NewCrsRuleLoader loads and parses CRS files from disk.
func NewCrsRuleLoader(parser RuleParser) RuleLoader {
	return &crsRuleLoader{parser}
}

var ruleSetPathsMap = map[waf.RuleSetID][]string{
	"testruleset": {
		"testruleset/testruleset.conf",
	},
	"OWASP CRS 3.0": {
		"crs3.0/crs-setup.appgw.conf",
		"crs3.0/rules/REQUEST-901-INITIALIZATION.conf",
		"crs3.0/rules/REQUEST-903.9001-DRUPAL-EXCLUSION-RULES.conf",
		"crs3.0/rules/REQUEST-903.9002-WORDPRESS-EXCLUSION-RULES.conf",
		"crs3.0/rules/REQUEST-905-COMMON-EXCEPTIONS.conf",
		"crs3.0/rules/REQUEST-910-IP-REPUTATION.conf",
		"crs3.0/rules/REQUEST-911-METHOD-ENFORCEMENT.conf",
		"crs3.0/rules/REQUEST-912-DOS-PROTECTION.conf",
		"crs3.0/rules/REQUEST-913-SCANNER-DETECTION.conf",
		"crs3.0/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
		"crs3.0/rules/REQUEST-921-PROTOCOL-ATTACK.conf",
		"crs3.0/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf",
		"crs3.0/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf",
		"crs3.0/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf",
		"crs3.0/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf",
		"crs3.0/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf",
		"crs3.0/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
		"crs3.0/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf",
		"crs3.0/rules/REQUEST-949-BLOCKING-EVALUATION.conf",
	},
}

// GetRules loads and parses CRS files from disk.
func (c *crsRuleLoader) Rules(ruleSetID waf.RuleSetID) (statements []Statement, err error) {
	paths, ok := ruleSetPathsMap[ruleSetID]
	if !ok {
		err = fmt.Errorf("unsupported ruleset: %s", ruleSetID)
		return
	}

	crsRulesPath := getCrsRulesPath()
	for _, crsFile := range paths {
		fullPath := filepath.Join(crsRulesPath, crsFile)
		var bb []byte
		bb, err = ioutil.ReadFile(fullPath)
		if err != nil {
			err = fmt.Errorf("Failed to load rule file %s. Error: %s", fullPath, err)
			return
		}

		var rr []Statement
		phraseLoaderCb := func(fileName string) ([]string, error) {
			return loadPhraseFile(path.Join(path.Dir(fullPath), fileName))
		}
		rr, err = c.parser.Parse(string(bb), phraseLoaderCb)
		if err != nil {
			err = fmt.Errorf("Got unexpected error while loading rule file %s. Error: %s", fullPath, err)
			return
		}

		var filteredStatements []Statement
		for _, r := range rr {
			rule, ok := r.(*Rule)
			if ok {
				// Skip this rule until we add support for backreferences
				// TODO add support for backreferences
				if rule.ID == 942130 {
					log.Warn().Int("ruleID", 942130).Msg("Skipping rule due to lack of support for backreferences")
					continue
				}

				// Skip this rule until we add support for stripping embedded anchors
				// TODO add support for stripping embedded anchors
				if rule.ID == 942330 {
					log.Warn().Int("ruleID", 942330).Msg("Skipping rule due to lack of support for embedded anchors")
					continue
				}

				// Skip this rule until we add full support numerical operations
				// TODO add full support numerical operations
				if rule.ID == 920130 {
					log.Warn().Int("ruleID", 920130).Msg("Skipping rule due to lack of add full support numerical operations")
					continue
				}

				// Skip this rule until we add full support numerical operations
				// TODO add full support numerical operations
				if rule.ID == 920140 {
					log.Warn().Int("ruleID", 920140).Msg("Skipping rule due to lack of add full support numerical operations")
					continue
				}

				// Skip this rule until we add support for target REQUEST_PROTOCOL
				// TODO add support for target REQUEST_PROTOCOL
				if rule.ID == 920430 {
					log.Warn().Int("ruleID", 920430).Msg("Skipping rule due to lack of add support for target REQUEST_PROTOCOL")
					continue
				}

				// Skip this rule until we add support for target REQUEST_METHOD
				// TODO add support for target REQUEST_METHOD
				if rule.ID == 911100 {
					log.Warn().Int("ruleID", 911100).Msg("Skipping rule due to lack of add support for target REQUEST_METHOD")
					continue
				}
			}

			filteredStatements = append(filteredStatements, r)
		}

		statements = append(statements, filteredStatements...)
	}

	return
}

func getCrsRulesPath() string {
	execPath, _ := os.Executable()
	dir := filepath.Join(filepath.Dir(execPath), "rulesetfiles")

	// Was this a tmp bin file started by "go run" or "dlv"?
	startedByDlv := strings.HasSuffix(execPath, "/debug")
	startedByGoRun := strings.Contains(strings.Replace(dir, "\\", "/", -1), "/go-build")
	if startedByDlv || startedByGoRun {
		// Instead use the rule files in the source tree
		_, s, _, _ := runtime.Caller(0)
		s = filepath.Dir(s)
		dir = filepath.Join(s, "rulesetfiles")
	}

	return dir
}

type phraseLoaderCb func(string) ([]string, error)

func loadPhraseFile(fullPath string) (phrases []string, err error) {
	var bb []byte
	bb, err = ioutil.ReadFile(fullPath)
	if err != nil {
		err = fmt.Errorf("Failed to load phrase file %s. Error: %s", fullPath, err)
		return
	}

	s := string(bb)
	raw := strings.Split(s, "\n")
	for _, p := range raw {
		if p != "" && !strings.HasPrefix(p, "#") {
			phrases = append(phrases, p)
		}
	}
	return
}
