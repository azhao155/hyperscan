package secrule

import (
	"azwaf/waf"
	"fmt"
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
	fs     RuleLoaderFileSystem
}

// NewCrsRuleLoader loads and parses CRS files from disk.
func NewCrsRuleLoader(parser RuleParser, fs RuleLoaderFileSystem) RuleLoader {
	return &crsRuleLoader{
		parser: parser,
		fs:     fs,
	}
}

var ruleSetPathsMap = map[waf.RuleSetID][]string{
	"OWASP CRS 3.0": {"crs3.0/main.conf"},
	"OWASP CRS 3.0 with config for regression tests": {"crs3.0/main.regressiontesting.conf"},
}

type includeLoaderCb func(filePath string) (statements []Statement, err error)

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
		var rr []Statement
		rr, err = loadRulesFromPath(fullPath, c.parser, c.fs, nil)
		if err != nil {
			return
		}
		statements = append(statements, filterUnsupportedRules(rr)...)
	}

	return
}

func loadRulesFromPath(filePath string, parser RuleParser, fs RuleLoaderFileSystem, parentIncludeFiles []string) (statements []Statement, err error) {
	// Guard against cyclic includes
	filePath, err = fs.Abs(filePath)
	if err != nil {
		err = fmt.Errorf("failed get absolute path for %s: %s", filePath, err)
		return
	}
	filePath, err = fs.EvalSymlinks(filePath)
	if err != nil {
		err = fmt.Errorf("failed to eval symlinks for %s: %s", filePath, err)
		return
	}
	for _, f := range parentIncludeFiles {
		if filePath == f {
			err = fmt.Errorf("cyclic include detect in config file %s", filePath)
			return
		}
	}
	parentIncludeFiles = append(parentIncludeFiles, filePath)

	// Actual read from disk
	var bb []byte
	bb, err = fs.ReadFile(filePath)
	if err != nil {
		err = fmt.Errorf("failed to read rule file %s: %s", filePath, err)
		return
	}

	phraseLoaderCb := func(fileName string) ([]string, error) {
		return loadPhraseFile(path.Join(path.Dir(filePath), fileName))
	}

	includeLoaderCb := func(includeFilePath string) (statements []Statement, err error) {
		p := includeFilePath
		if !filepath.IsAbs(includeFilePath) {
			p = path.Join(path.Dir(filePath), includeFilePath)
		}
		return loadRulesFromPath(p, parser, fs, parentIncludeFiles)
	}

	rr, err := parser.Parse(string(bb), phraseLoaderCb, includeLoaderCb)
	if err != nil {
		err = fmt.Errorf("error while parsing rule file %s: %s", filePath, err)
		return
	}

	statements = append(statements, filterUnsupportedRules(rr)...)

	return
}

func filterUnsupportedRules(stmts []Statement) (filteredStmts []Statement) {
	for _, r := range stmts {
		rule, ok := r.(*Rule)
		if ok {
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

			// Skip this rule until we add full support numerical operations
			// TODO add full support numerical operations
			if rule.ID == 920130 {
				continue
			}

			// Skip this rule until we add full support numerical operations
			// TODO add full support numerical operations
			if rule.ID == 920140 {
				continue
			}

			// Skip this rule until we add support for target REQUEST_PROTOCOL
			// TODO add support for target REQUEST_PROTOCOL
			if rule.ID == 920430 {
				continue
			}

			// Skip this rule until we add support for target REQUEST_METHOD
			// TODO add support for target REQUEST_METHOD
			if rule.ID == 911100 {
				continue
			}
		}

		filteredStmts = append(filteredStmts, r)
	}

	return
}

func getCrsRulesPath() string {
	execPath, _ := os.Executable()
	dir := filepath.Join(filepath.Dir(execPath), "rulesetfiles")

	// Was this a tmp bin file started by "go run" or "dlv"?
	startedByDlv := strings.HasSuffix(execPath, "/debug") || strings.HasSuffix(execPath, "/debug.test")
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

type standaloneRuleLoader struct {
	parser                RuleParser
	fs                    RuleLoaderFileSystem
	secRuleConfigFilePath string
}

// NewStandaloneRuleLoader loads and parses SecRule files from disk, given a SecRule file path.
func NewStandaloneRuleLoader(parser RuleParser, fs RuleLoaderFileSystem, secRuleConfigFilePath string) RuleLoader {
	return &standaloneRuleLoader{
		parser:                parser,
		fs:                    fs,
		secRuleConfigFilePath: secRuleConfigFilePath,
	}
}

// GetRules loads and parses a SecRule config file from disk (given in the constructor).
func (c *standaloneRuleLoader) Rules(ruleSetID waf.RuleSetID) (statements []Statement, err error) {
	statements, err = loadRulesFromPath(c.secRuleConfigFilePath, c.parser, c.fs, nil)
	if err != nil {
		return
	}

	return
}

// RuleLoaderFileSystem is the file system functions the rule loader needs. Needed for mocking.
type RuleLoaderFileSystem interface {
	ReadFile(filename string) ([]byte, error)
	Abs(path string) (string, error)
	EvalSymlinks(path string) (string, error)
}

// NewRuleLoaderFileSystem creates a RuleLoaderFileSystem that uses the real OS file system.
func NewRuleLoaderFileSystem() RuleLoaderFileSystem {
	return &ruleLoaderFileSystemImpl{}
}

type ruleLoaderFileSystemImpl struct{}

func (f *ruleLoaderFileSystemImpl) ReadFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}
func (f *ruleLoaderFileSystemImpl) Abs(path string) (string, error) {
	return filepath.Abs(path)
}
func (f *ruleLoaderFileSystemImpl) EvalSymlinks(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}
