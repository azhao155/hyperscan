package secrule

import (
	"azwaf/waf"
	"fmt"
	"github.com/rs/zerolog"
)

// NewEngineFactory creates a factory that can create SecRule engines.
func NewEngineFactory(logger zerolog.Logger, rl RuleLoader, rsf ReqScannerFactory, re RuleEvaluator, reslog ResultsLogger) waf.SecRuleEngineFactory {
	return &engineFactoryImpl{
		logger:            logger,
		ruleLoader:        rl,
		reqScannerFactory: rsf,
		ruleEvaluator:     re,
		resultsLogger:     reslog,
	}
}

type engineFactoryImpl struct {
	logger            zerolog.Logger
	ruleLoader        RuleLoader
	reqScannerFactory ReqScannerFactory
	ruleEvaluator     RuleEvaluator
	resultsLogger     ResultsLogger
}

func (f *engineFactoryImpl) NewEngine(config waf.SecRuleConfig) (engine waf.SecRuleEngine, err error) {
	ruleSetID := waf.RuleSetID(config.RuleSetID())
	f.logger.Info().Str("ruleSet", string(ruleSetID)).Msg("Loading rules")

	statements, err := f.ruleLoader.Rules(ruleSetID)
	if err != nil {
		err = fmt.Errorf("failed to load ruleset %v: %v", ruleSetID, err)
		return
	}

	reqScanner, err := f.reqScannerFactory.NewReqScanner(statements)
	if err != nil {
		err = fmt.Errorf("failed to create request scanner: %v", err)
		return
	}

	// Buffered channel used for reuse of scratch spaces between requests, while not letting concurrent requests share the same scratch space.
	scratchSpaceNext := make(chan *ReqScannerScratchSpace, 100000)
	s, err := reqScanner.NewScratchSpace()
	if err != nil {
		panic(err)
	}
	scratchSpaceNext <- s

	engine = &engineImpl{
		statements:       statements,
		reqScanner:       reqScanner,
		ruleEvaluator:    f.ruleEvaluator,
		resultsLogger:    f.resultsLogger,
		scratchSpaceNext: scratchSpaceNext,
	}

	return
}
