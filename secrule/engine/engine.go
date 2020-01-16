package engine

import (
	sr "azwaf/secrule"
	ast "azwaf/secrule/ast"
	rs "azwaf/secrule/reqscanning"
	re "azwaf/secrule/ruleevaluation"

	"azwaf/waf"
	"regexp"

	"github.com/rs/zerolog"
)

type engineImpl struct {
	statements                     []ast.Statement
	reqScanner                     sr.ReqScanner
	scratchSpaceNext               chan *sr.ReqScannerScratchSpace
	ruleEvaluatorFactory           sr.RuleEvaluatorFactory
	usesFullRawRequestBody         bool
	ruleSetID                      waf.RuleSetID
	txTargetRegexSelectorsCompiled map[string]*regexp.Regexp
}

// NewEngine creates a SecRule engine from statements
func NewEngine(statements []ast.Statement, rsf sr.ReqScannerFactory, ref sr.RuleEvaluatorFactory, ruleSetID waf.RuleSetID) (engine waf.SecRuleEngine, err error) {
	reqScanner, err := rsf.NewReqScanner(statements)
	if err != nil {
		return
	}

	// Buffered channel used for reuse of scratch spaces between requests, while not letting concurrent requests share the same scratch space.
	scratchSpaceNext := make(chan *sr.ReqScannerScratchSpace, 100000)
	s, err := reqScanner.NewScratchSpace()
	if err != nil {
		panic(err)
	}
	scratchSpaceNext <- s

	usesFullRawRequestBody := usesRequestBodyTarget(statements)

	// CRS has a few rules that uses regex selectors on TX-targets such as "SecRule TX:/^HEADER_NAME_/ ...", so we will precompile these regexes.
	txTargetRegexSelectorsCompiled, err := re.GetTxTargetRegexSelectorsCompiled(statements)
	if err != nil {
		return
	}

	engine = &engineImpl{
		statements:                     statements,
		reqScanner:                     reqScanner,
		ruleEvaluatorFactory:           ref,
		scratchSpaceNext:               scratchSpaceNext,
		usesFullRawRequestBody:         usesFullRawRequestBody,
		ruleSetID:                      ruleSetID,
		txTargetRegexSelectorsCompiled: txTargetRegexSelectorsCompiled,
	}

	return
}

type secRuleEvaluationImpl struct {
	logger               zerolog.Logger
	resultsLogger        waf.SecRuleResultsLogger
	engine               *engineImpl
	request              waf.HTTPRequest
	reqBodyType          waf.ReqBodyType
	scanResults          *sr.ScanResults
	ruleTriggeredCb      func(stmt ast.Statement, decision waf.Decision, msg string, logData string)
	reqScannerEvaluation sr.ReqScannerEvaluation
	scratchSpaceNext     chan *sr.ReqScannerScratchSpace
	scratchSpace         *sr.ReqScannerScratchSpace
	ruleEvaluator        sr.RuleEvaluator
	env                  sr.Environment
}

func (s *engineImpl) NewEvaluation(logger zerolog.Logger, resultsLogger waf.SecRuleResultsLogger, req waf.HTTPRequest, reqBodyType waf.ReqBodyType) waf.SecRuleEvaluation {
	ruleTriggeredCb := func(stmt ast.Statement, decision waf.Decision, msg string, logData string) {
		var ruleID int
		switch stmt := stmt.(type) {
		case *ast.Rule:
			ruleID = stmt.ID
		case *ast.ActionStmt:
			ruleID = stmt.ID
		}

		// ModSec truncates these fields to 512 bytes, so we will too.
		if len(msg) > 512 {
			msg = msg[:512-3] + "..."
		}
		if len(logData) > 512 {
			logData = logData[:512-3] + "..."
		}

		logger.Info().Int("ruleID", ruleID).Int("decision", int(decision)).Str("msg", msg).Str("logData", logData).Msg("SecRule triggered")

		resultsLogger.SecRuleTriggered(ruleID, decision, msg, logData, s.ruleSetID)
	}

	// Reuse a scratch space, or create a new one if there are none available
	var scratchSpace *sr.ReqScannerScratchSpace
	if len(s.scratchSpaceNext) > 0 {
		scratchSpace = <-s.scratchSpaceNext
	} else {
		var err error
		scratchSpace, err = s.reqScanner.NewScratchSpace()
		if err != nil {
			panic(err)
		}
	}

	reqScannerEvaluation := s.reqScanner.NewReqScannerEvaluation(scratchSpace)

	env := re.NewEnvironment(s.txTargetRegexSelectorsCompiled)
	env.Set(ast.EnvVarReqbodyProcessorError, "", ast.Value{ast.IntToken(0)})
	env.Set(ast.EnvVarReqbodyProcessor, "", reqbodyProcessorValues[reqBodyType]) // This is needed in the env to later populate the REQBODY_PROCESSOR target.

	scanResults := rs.NewScanResults()

	ruleEvaluator := s.ruleEvaluatorFactory.NewRuleEvaluator(logger, env, s.statements, scanResults, ruleTriggeredCb)

	return &secRuleEvaluationImpl{
		request:              req,
		reqBodyType:          reqBodyType,
		resultsLogger:        resultsLogger,
		logger:               logger,
		engine:               s,
		scanResults:          scanResults,
		ruleTriggeredCb:      ruleTriggeredCb,
		reqScannerEvaluation: reqScannerEvaluation,
		scratchSpaceNext:     s.scratchSpaceNext,
		scratchSpace:         scratchSpace,
		ruleEvaluator:        ruleEvaluator,
		env:                  env,
	}
}

func (s *secRuleEvaluationImpl) AlsoScanFullRawRequestBody() bool {
	// The secrule engine needs the full raw request body if it has statements that uses it, and content type is application/x-www-form-urlencoded.
	if s.engine.usesFullRawRequestBody && s.reqBodyType == waf.URLEncodedBody {
		return true
	}

	// Alternatively a rule could have run a control action "ctl:forceRequestBodyVariable=On".
	if s.ruleEvaluator.IsForceRequestBodyScanning() {
		return true
	}

	return false
}

func (s *secRuleEvaluationImpl) ScanHeaders() (err error) {
	err = s.reqScannerEvaluation.ScanHeaders(s.request, s.scanResults)
	if err != nil {
		return
	}

	s.env.Set(ast.EnvVarRequestLine, "", ast.Value{ast.StringToken(s.scanResults.RequestLine)})
	s.env.Set(ast.EnvVarRequestMethod, "", ast.Value{ast.StringToken(s.scanResults.RequestMethod)})
	s.env.Set(ast.EnvVarRequestProtocol, "", ast.Value{ast.StringToken(s.scanResults.RequestProtocol)})
	s.env.Set(ast.EnvVarRequestHeaders, "host", ast.Value{ast.StringToken(s.scanResults.HostHeader)})

	return
}

func (s *secRuleEvaluationImpl) ScanBodyField(contentType waf.FieldContentType, fieldName string, data string) (err error) {
	return s.reqScannerEvaluation.ScanBodyField(contentType, fieldName, data, s.scanResults)
}

func (s *secRuleEvaluationImpl) EvalRulesPhase1() (wafDecision waf.Decision) {
	return s.evalRules(1)
}

func (s *secRuleEvaluationImpl) EvalRulesPhase2to5() (wafDecision waf.Decision) {
	s.populateMultipartStrictnessResults()

	for phase := 2; phase <= 5; phase++ {
		wafDecision = s.evalRules(phase)
		if wafDecision == waf.Allow || wafDecision == waf.Block {
			return
		}
	}

	return
}

func (s *secRuleEvaluationImpl) BodyParseErrorOccurred() {
	s.env.Set(ast.EnvVarReqbodyProcessorError, "", ast.Value{ast.IntToken(1)})
}

func (s *secRuleEvaluationImpl) evalRules(phase int) (wafDecision waf.Decision) {
	if s.logger.Debug() != nil {
		for key, matches := range s.scanResults.Matches {
			for _, match := range matches {
				s.logger.Debug().
					Int("ruleID", key.RuleID).
					Int("ruleItemIdx", key.RuleItemIdx).
					Str("targetName", ast.TargetNamesStrings[key.Target.Name]).
					Str("targetSelector", key.Target.Selector).
					Str("matchedData", string(match.Data)).
					Msg("Request scanning found a match")
			}
		}
	}

	wafDecision = s.ruleEvaluator.ProcessPhase(phase)
	s.logger.Debug().Int("wafDecision", int(wafDecision)).Msg("SecRule engine rule evaluation decision")

	return
}

// Release resources.
func (s *secRuleEvaluationImpl) Close() {
	s.scratchSpaceNext <- s.scratchSpace
}

func usesRequestBodyTarget(statements []ast.Statement) bool {
	for _, stmt := range statements {
		switch stmt := stmt.(type) {
		case *ast.Rule:
			for _, ruleItem := range stmt.Items {
				for _, target := range ruleItem.Predicate.Targets {
					if target.Name == ast.TargetRequestBody {
						return true
					}
				}
			}
		}
	}

	return false
}

func (s *secRuleEvaluationImpl) populateMultipartStrictnessResults() {
	boolToVal := func(b bool) ast.Value {
		if b {
			return ast.Value{ast.IntToken(1)}
		}
		return ast.Value{ast.IntToken(0)}
	}

	// As per the ModSecurity reference manual.
	e := s.env.Get(ast.EnvVarReqbodyProcessorError, "")
	reqbodyProcessorError := (len(e) > 0 && e[0].(ast.IntToken) == 1)
	reqbodyProcessorError = reqbodyProcessorError || s.scanResults.MultipartIncomplete // Considering an incomplete form-data body an error. Probably EnvVarReqbodyProcessorError was already set due to this though.
	multipartStrictError := reqbodyProcessorError ||
		s.scanResults.MultipartBoundaryQuoted ||
		s.scanResults.MultipartBoundaryWhitespace ||
		s.scanResults.MultipartDataAfter ||
		s.scanResults.MultipartDataBefore ||
		s.scanResults.MultipartFileLimitExceeded ||
		s.scanResults.MultipartHeaderFolding ||
		s.scanResults.MultipartInvalidHeaderFolding ||
		s.scanResults.MultipartInvalidQuoting ||
		s.scanResults.MultipartLfLine ||
		s.scanResults.MultipartMissingSemicolon ||
		s.scanResults.MultipartStrictError

	s.env.Set(ast.EnvVarMultipartBoundaryQuoted, "", boolToVal(s.scanResults.MultipartBoundaryQuoted))
	s.env.Set(ast.EnvVarMultipartBoundaryWhitespace, "", boolToVal(s.scanResults.MultipartBoundaryWhitespace))
	s.env.Set(ast.EnvVarMultipartDataAfter, "", boolToVal(s.scanResults.MultipartDataAfter))
	s.env.Set(ast.EnvVarMultipartDataBefore, "", boolToVal(s.scanResults.MultipartDataBefore))
	s.env.Set(ast.EnvVarMultipartFileLimitExceeded, "", boolToVal(s.scanResults.MultipartFileLimitExceeded))
	s.env.Set(ast.EnvVarMultipartHeaderFolding, "", boolToVal(s.scanResults.MultipartHeaderFolding))
	s.env.Set(ast.EnvVarMultipartInvalidHeaderFolding, "", boolToVal(s.scanResults.MultipartInvalidHeaderFolding))
	s.env.Set(ast.EnvVarMultipartInvalidQuoting, "", boolToVal(s.scanResults.MultipartInvalidQuoting))
	s.env.Set(ast.EnvVarMultipartLfLine, "", boolToVal(s.scanResults.MultipartLfLine))
	s.env.Set(ast.EnvVarMultipartMissingSemicolon, "", boolToVal(s.scanResults.MultipartMissingSemicolon))
	s.env.Set(ast.EnvVarMultipartStrictError, "", boolToVal(multipartStrictError))
	s.env.Set(ast.EnvVarMultipartUnmatchedBoundary, "", boolToVal(s.scanResults.MultipartUnmatchedBoundary))
}

var reqbodyProcessorValues = []ast.Value{
	ast.Value{},
	ast.Value{ast.StringToken("MULTIPART")},
	ast.Value{ast.StringToken("URLENCODED")},
	ast.Value{ast.StringToken("XML")},
	ast.Value{ast.StringToken("JSON")},
}
