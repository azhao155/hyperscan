package hyperscan

import (
	"azwaf/secrule"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAllCrsReqRulesIndividually(t *testing.T) {
	// Arrange
	f := NewMultiRegexEngineFactory()
	p := secrule.NewRuleParser()
	// TODO Add more rulesets when they become supported
	dirs := []string{
		"crs2.2.9/base_rules/",
		"crs3.0/rules/",
	}
	_, thissrcfilename, _, _ := runtime.Caller(0)
	var errors strings.Builder
	for _, dir := range dirs {
		dir2 := filepath.Join(filepath.Dir(thissrcfilename), "../secrule/rulesetfiles", dir)
		files, err := ioutil.ReadDir(dir2)
		if err != nil {
			t.Fatal(err)
		}

		for _, file := range files {
			filename := file.Name()
			if !strings.HasSuffix(filename, ".conf") || !strings.Contains(filename, "REQUEST") {
				continue
			}

			b, err := ioutil.ReadFile(filepath.Join(dir2, filename))
			if err != nil {
				t.Fatalf("Failed to load rule file: %s", err)
			}

			rr, err := p.Parse(string(b))

			if err != nil {
				t.Fatalf("Got unexpected error while loading rule file: %s. Error: %s", filename, err)
			}

			for _, rule := range rr {
				// Skip this rule until we add support for backreferences
				// TODO add support for backreferences
				if rule.ID == 942130 {
					continue
				}

				// Skip this rule until we add support for stripping embedded anchors
				// TODO add support for stripping embedded anchors
				if rule.ID == 942330 {
					continue
				}

				for itemIdx, item := range rule.Items {
					if item.Op != secrule.Rx {
						continue
					}

					// Act
					e, err := f.NewMultiRegexEngine([]secrule.MultiRegexEnginePattern{
						{ID: 1, Expr: item.Val},
					})

					if e != nil {
						e.Close()
					}

					// Assert
					if err != nil {
						fmt.Fprintf(&errors, "Error with in ruleset %s, rule %d, item index %d, expression \"%s\". Error was: %s\n", dir, rule.ID, itemIdx, item.Val, err)
					}
				}
			}
		}
	}

	if errors.Len() > 0 {
		t.Fatalf("\n%s", errors.String())
	}
}
