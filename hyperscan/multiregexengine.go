package hyperscan

import (
	"azwaf/secrule"
	hs "github.com/flier/gohs/hyperscan"
)

// EngineFactory implements the multiRegexEngineFactory interface.
type EngineFactory struct {
}

// Engine implements the multiRegexEngine interface.
type Engine struct {
	// Hyperscan's compiled database of regexes
	db hs.BlockDatabase

	// Pre-allocated memory space that Hyperscan needs during evaluation
	scratch *hs.Scratch
}

// NewMultiRegexEngineFactory creates a secrule.MultiRegexEngineFactory.
func NewMultiRegexEngineFactory() secrule.MultiRegexEngineFactory {
	return &EngineFactory{}
}

// NewMultiRegexEngine creates a secrule.MultiRegexEngine.
func (f *EngineFactory) NewMultiRegexEngine(mm []secrule.MultiRegexEnginePattern) (m secrule.MultiRegexEngine, err error) {
	h := &Engine{}

	patterns := []*hs.Pattern{}
	for _, m := range mm {
		p := hs.NewPattern(m.Expr, 0)
		p.Id = m.ID

		// SingleMatch makes Hyperscan only return one match per regex. So if a regex is found multiple time, still only one match is recorded.
		// PrefilterMode gives broader regex compatibility, at the cost possible false positives. Potential matches therefore must be verified with another regex engine.
		p.Flags = hs.SingleMatch | hs.PrefilterMode

		patterns = append(patterns, p)
	}

	h.db, err = hs.NewBlockDatabase(patterns...)
	if err != nil {
		return
	}

	h.scratch, err = hs.NewScratch(h.db)
	if err != nil {
		h.db.Close()
		return
	}

	m = h
	return
}

// Scan scans the given input for all expressions that this engine was initialized with.
func (h *Engine) Scan(input []byte) (matches []secrule.MultiRegexEngineMatch, err error) {
	matches = []secrule.MultiRegexEngineMatch{}
	handler := func(id uint, from, to uint64, flags uint, context interface{}) error {
		// TODO Hyperscan doesn't populate "from" by default
		m := secrule.MultiRegexEngineMatch{
			ID:     int(id),
			EndPos: int(to),
		}
		matches = append(matches, m)
		return nil
	}

	err = h.db.Scan(input, h.scratch, handler, nil)
	return
}
