package secrule

import (
	ast "azwaf/secrule/ast"

	"azwaf/waf"

	"github.com/rs/zerolog"
)

// RuleEvaluatorFactory creates RuleEvaluator instances.
type RuleEvaluatorFactory interface {
	NewRuleEvaluator(logger zerolog.Logger, perRequestEnv Environment, statements []ast.Statement, scanResults *ScanResults, triggeredCb RuleEvaluatorTriggeredCb) RuleEvaluator
}

// RuleEvaluatorTriggeredCb is will be called when the rule evaluator has decided that a rule is triggered.
type RuleEvaluatorTriggeredCb = func(stmt ast.Statement, decision waf.Decision, msg string, logData string)

// RuleLoader obtains rules for a given rule set.
type RuleLoader interface {
	Rules(r waf.RuleSetID) (statements []ast.Statement, err error)
}

// StandaloneRuleLoader loads a fixed set of rules defined at the creation of the StandaloneRuleLoader object.
type StandaloneRuleLoader interface {
	Rules() (statements []ast.Statement, err error)
}

// RuleEvaluator processes the incoming request against all parsed rules
type RuleEvaluator interface {
	ProcessPhase(phase int) (decision waf.Decision)
	IsForceRequestBodyScanning() bool
}

// PhraseLoaderCb will be called when the rule loader needs to load a phrase file.
type PhraseLoaderCb func(string) ([]string, error)

// IncludeLoaderCb will be called when the rule parser reaches an include-statement.
type IncludeLoaderCb func(filePath string) (statements []ast.Statement, err error)

// RuleParser parses SecRule language files.
type RuleParser interface {
	Parse(input string, pf PhraseLoaderCb, ilcb IncludeLoaderCb) (statements []ast.Statement, err error)
}

// ReqScanner can create NewReqScannerEvaluations, which scans requests for string matches and other properties that the rule engine will be needing to do rule evaluation.
type ReqScanner interface {
	NewReqScannerEvaluation(scratchSpace *ReqScannerScratchSpace) ReqScannerEvaluation
	NewScratchSpace() (scratchSpace *ReqScannerScratchSpace, err error)
}

// ReqScannerScratchSpace is a collection of all the scratch spaces a ReqScanner will need. These can be reused for different requests, but cannot be shared concurrently.
type ReqScannerScratchSpace map[*waf.MultiRegexEngine]waf.MultiRegexEngineScratchSpace

// ReqScannerEvaluation is a session of the ReqScanner.
type ReqScannerEvaluation interface {
	ScanHeaders(req waf.HTTPRequest, results *ScanResults) (err error)
	ScanBodyField(contentType waf.FieldContentType, fieldName string, data string, results *ScanResults) error
}

// ReqScannerFactory creates ReqScanners. This makes mocking possible when testing.
type ReqScannerFactory interface {
	NewReqScanner(statements []ast.Statement, exclusions []waf.Exclusion) (r ReqScanner, err error)
}

// Environment holds the per-request variables and other state information as the rule evaluator is executing.
type Environment interface {
	Get(name ast.EnvVarName, selector string) (v ast.Value)
	GetTxVarsViaRegexSelector(selector string) (vv []ast.Value)
	Set(name ast.EnvVarName, collectionKey string, val ast.Value)
	Delete(name ast.EnvVarName, selector string)
	GetCollection(name ast.EnvVarName) (vv []ast.Value)
	ResetMatchesCollections()
	UpdateMatches(matches []Match)
	ExpandMacros(v ast.Value) (output ast.Value)
}

// Match represents when a match was found during the request scanning phase.
type Match struct {
	Data               []byte
	CaptureGroups      [][]byte
	EntireFieldContent []byte
	TargetName         ast.TargetName
	FieldName          []byte
}

// ScanResults is the collection of all results found while scanning.
type ScanResults struct {
	Matches                       map[MatchKey][]Match
	TargetsCount                  map[ast.Target]int
	RequestLine                   []byte
	RequestMethod                 []byte
	RequestProtocol               []byte
	HostHeader                    []byte
	MultipartBoundaryQuoted       bool
	MultipartBoundaryWhitespace   bool
	MultipartDataAfter            bool
	MultipartDataBefore           bool
	MultipartFileLimitExceeded    bool
	MultipartHeaderFolding        bool
	MultipartIncomplete           bool
	MultipartInvalidHeaderFolding bool
	MultipartInvalidQuoting       bool
	MultipartLfLine               bool
	MultipartMissingSemicolon     bool
	MultipartStrictError          bool
	MultipartUnmatchedBoundary    bool
}

// MatchKey is used as a key to look up a match in a ScanResults.
type MatchKey struct {
	RuleID      int
	RuleItemIdx int
	Target      ast.Target
}

// GetResultsFor returns any results for matches that were done during the request scanning.
func (r *ScanResults) GetResultsFor(ruleID int, ruleItemIdx int, target ast.Target) (mm []Match, ok bool) {
	mm, ok = r.Matches[MatchKey{RuleID: ruleID, RuleItemIdx: ruleItemIdx, Target: target}]
	return
}
