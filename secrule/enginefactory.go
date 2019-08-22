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

	// Coordination to reuse scratch spaces between requests, while not letting concurrent requests share the same scratch space.
	scratchSpaceDone := make(chan *ReqScannerScratchSpace)
	scratchSpaceNext := make(chan *ReqScannerScratchSpace)
	go func() {
		var availableScratchSpaces []*ReqScannerScratchSpace

		// Pre-allocate some scratch space sets. For example for CRS 3.0, each one is around 55KiB.
		for i := 0; i < 200; i++ {
			s, err := reqScanner.NewScratchSpace()
			if err != nil {
				panic(err)
			}

			availableScratchSpaces = append(availableScratchSpaces, s)
		}

		var nextAvailable *ReqScannerScratchSpace

		for {
			if nextAvailable == nil {
				// Pop the next available scratch space
				nextAvailable = availableScratchSpaces[len(availableScratchSpaces)-1]
				availableScratchSpaces = availableScratchSpaces[:len(availableScratchSpaces)-1]

				// No more scratch spaces ready standby. Create one so we have it ready in case someone asks before we get one back.
				if len(availableScratchSpaces) == 0 {
					s, err := reqScanner.NewScratchSpace()
					if err != nil {
						panic(err)
					}

					availableScratchSpaces = append(availableScratchSpaces, s)
				}
			}

			select {
			case scratchSpaceNext <- nextAvailable:
				nextAvailable = nil
			case s := <-scratchSpaceDone:
				availableScratchSpaces = append(availableScratchSpaces, s)
				// TODO consider freeing scratch spaces if the number of available scratch spaces become very large for a long time.
			}
		}
	}()

	engine = &engineImpl{
		statements:       statements,
		reqScanner:       reqScanner,
		ruleEvaluator:    f.ruleEvaluator,
		resultsLogger:    f.resultsLogger,
		scratchSpaceDone: scratchSpaceDone,
		scratchSpaceNext: scratchSpaceNext,
	}

	return
}
