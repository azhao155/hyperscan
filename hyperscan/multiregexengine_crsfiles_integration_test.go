package hyperscan

import (
	ast "azwaf/secrule/ast"
	srrp "azwaf/secrule/ruleparsing"

	"azwaf/waf"
	"fmt"
	"io/ioutil"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAllCrsReqRulesIndividually(t *testing.T) {
	// Arrange
	f := NewMultiRegexEngineFactory(nil)
	p := srrp.NewRuleParser()

	// TODO Add more rulesets when they become supported
	files := []string{
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
	}
	_, thissrcfilename, _, _ := runtime.Caller(0)
	var errors strings.Builder

	for _, file := range files {
		fullPath := filepath.Join(filepath.Dir(thissrcfilename), "../secrule/rulesetfiles", file)
		b, err := ioutil.ReadFile(fullPath)
		if err != nil {
			t.Fatalf("Failed to load rule file: %s", err)
		}

		phraseLoaderCb := func(fileName string) ([]string, error) {
			return loadPhraseFile(path.Join(path.Dir(fullPath), fileName))
		}

		rr, err := p.Parse(string(b), phraseLoaderCb, nil)

		if err != nil {
			t.Fatalf("Got unexpected error while loading rule file: %s. Error: %s", fullPath, err)
		}

		for _, rule := range rr {
			rule, ok := rule.(*ast.Rule)
			if !ok {
				continue
			}

			// Skip this rule until we add support for backreferences
			// TODO add support for backreferences
			if rule.ID == 942130 {
				continue
			}

			for itemIdx, item := range rule.Items {
				if item.Predicate.Op != ast.Rx {
					continue
				}

				if len(item.Predicate.Val) != 1 {
					continue
				}

				tok, ok := item.Predicate.Val[0].(ast.StringToken)
				if !ok {
					continue
				}

				// Act
				e, err := f.NewMultiRegexEngine([]waf.MultiRegexEnginePattern{
					{ID: 1, Expr: string(tok)},
				})

				if e != nil {
					e.Close()
				}

				// Assert
				if err != nil {
					fmt.Fprintf(&errors, "Error with in rule file %v, rule %d, item index %d, expression \"%s\". Error was: %s\n", fullPath, rule.ID, itemIdx, item.Predicate.Val, err)
				}
			}
		}
	}

	if errors.Len() > 0 {
		t.Fatalf("\n%s", errors.String())
	}
}

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
