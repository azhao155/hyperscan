package secrule

import (
	"azwaf/waf"
	"strings"
	"testing"
)

func TestCrsRuleLoader(t *testing.T) {
	// Arrange
	mrlfs := &mockRuleLoaderFileSystem{}
	mrp := &mockRuleParser{}
	rl := NewCrsRuleLoader(mrp, mrlfs)

	// Act
	err, _ := rl.Rules("OWASP CRS 3.0")

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
}

func TestStandaloneRuleLoader(t *testing.T) {
	// Arrange
	mrlfs := &mockRuleLoaderFileSystem{}
	mrp := &mockRuleParser{}
	rl := NewStandaloneRuleLoader(mrp, mrlfs, "file1.conf")

	// Act
	_, err := rl.Rules()

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
}

func TestStandaloneRuleLoaderCycle(t *testing.T) {
	// Arrange
	mrlfs := &mockRuleLoaderFileSystem{}
	mrp := NewRuleParser() // Use a real rule parser
	rl := NewStandaloneRuleLoader(mrp, mrlfs, "/fileCycle1.conf")

	// Act
	_, err := rl.Rules()

	// Assert
	if err == nil {
		t.Fatalf("Expected an error but got nil")
	}

	if !strings.Contains(err.Error(), "cyclic include detect in config file /fileCycle1.conf") {
		t.Fatalf("Did not get cyclic include error. Got: %s", err)
	}
}

type mockRuleParser struct{}

func (p *mockRuleParser) Parse(input string, pf phraseLoaderCb, ilcb includeLoaderCb) (statements []Statement, err error) {
	return
}

var mockFSFiles = map[string]string{
	"file1.conf":               `SecRule ARGS helloworld "id:12345,deny"`,
	"/fileCycle1.conf":         "include /someDir/fileCycle2.conf",
	"/someDir/fileCycle2.conf": "include fileCycle3.conf",
	"/someDir/fileCycle3.conf": "include ../fileCycle1.conf",
}

type mockRuleLoaderFileSystem struct{}

func (f *mockRuleLoaderFileSystem) ReadFile(filename string) ([]byte, error) {
	if s, ok := mockFSFiles[filename]; ok {
		return []byte(s), nil
	}

	return nil, nil

}
func (f *mockRuleLoaderFileSystem) Abs(path string) (string, error)          { return path, nil }
func (f *mockRuleLoaderFileSystem) EvalSymlinks(path string) (string, error) { return path, nil }

func newMockRuleLoader() RuleLoader {
	return &mockRuleLoader{}
}

type mockRuleLoader struct{}

func (m *mockRuleLoader) Rules(r waf.RuleSetID) (statements []Statement, err error) {
	statements = []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: Value{StringToken("ab+c")}},
				},
			},
		},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: Value{StringToken("abc+")}},
				},
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: Value{StringToken("xyz")}},
					Transformations: []Transformation{Lowercase},
				},
			},
		},
		&Rule{
			ID: 300,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "REQUEST_URI_RAW"}}, Op: Rx, Val: Value{StringToken("a+bc")}},
					Transformations: []Transformation{Lowercase, RemoveWhitespace},
				},
			},
		},
		&Rule{
			ID: 400,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "XML", Selector: "/*"}}, Op: Rx, Val: Value{StringToken("abc+")}},
				},
			},
		}}

	return
}
