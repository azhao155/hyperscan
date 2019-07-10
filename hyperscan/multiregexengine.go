package hyperscan

import (
	"azwaf/secrule"
	"fmt"
	hs "github.com/flier/gohs/hyperscan"
	log "github.com/sirupsen/logrus"
	"regexp"
)

type engineFactoryImpl struct {
	dbCache DbCache
}

type engineImpl struct {
	// Hyperscan's compiled database of regexes.
	db hs.BlockDatabase

	// Pre-allocated memory space that Hyperscan needs during evaluation.
	scratch *hs.Scratch

	// Precompiled Go regexes used to re-validate matches.
	goregexes map[int]*regexp.Regexp // TODO could this have been just a list rather than map?
}

// NewMultiRegexEngineFactory creates a MultiRegexEngineFactory which will create Hyperscan based MultiRegexEngines. DbCache is used to speed up initializing databases that was previously already built. This can be nil if you do not want to use a cache.
func NewMultiRegexEngineFactory(dbCache DbCache) secrule.MultiRegexEngineFactory {
	return &engineFactoryImpl{dbCache: dbCache}
}

// NewMultiRegexEngine creates a MultiRegexEngine that uses Hyperscan in prefilter mode for the initial scan, and then uses Go regexp to re-validate matches and extract strings.
func (f *engineFactoryImpl) NewMultiRegexEngine(mm []secrule.MultiRegexEnginePattern) (engine secrule.MultiRegexEngine, err error) {
	h := &engineImpl{}

	patterns := []*hs.Pattern{}
	for _, m := range mm {
		p := hs.NewPattern(m.Expr, 0)
		p.Id = m.ID

		// SingleMatch makes Hyperscan only return one match per regex. So if a regex is found multiple time, still only one match is recorded.
		// PrefilterMode gives broader regex compatibility, at the cost possible false positives. Potential matches therefore must be verified with another regex engine.
		p.Flags = hs.SingleMatch | hs.PrefilterMode

		patterns = append(patterns, p)
	}

	// Try to load precompiled database from cache.
	var cacheID string
	if f.dbCache != nil {
		cacheID = f.dbCache.cacheID(patterns)
		h.db = f.dbCache.loadFromCache(cacheID)

		log.WithFields(log.Fields{"cacheHit": h.db != nil}).Trace("Attempted Hyperscan DB load from cache")
	}

	// Build the Hyperscan database if cache miss.
	if h.db == nil {
		h.db, err = hs.NewBlockDatabase(patterns...)
		if err != nil {
			err = fmt.Errorf("failed to compile Hyperscan database with %d patterns: %v", len(patterns), err)
			return
		}

		if f.dbCache != nil {
			f.dbCache.saveToCache(cacheID, h.db)
		}
	}

	h.scratch, err = hs.NewScratch(h.db)
	if err != nil {
		h.Close()
		err = fmt.Errorf("failed to create Hyperscan scratch space: %v", err)
		return
	}

	// Compile each regex for Go regexp as well, so we can use Go regexp to re-validate matches that Hyperscan find as potential matches
	h.goregexes = make(map[int]*regexp.Regexp)
	for _, m := range mm {
		// Make the PCRE regex compatible with Go regexp
		e := removePcrePossessiveQuantifier(m.Expr)

		var r *regexp.Regexp
		r, err = regexp.Compile(e)
		if err != nil {
			err = fmt.Errorf("failed to compile Go regexp pattern %v. Error was: %v", e, err)
			h.Close()
			return
		}

		h.goregexes[m.ID] = r
	}

	engine = h
	return
}

// Scan scans the given input for all expressions that this engine was initialized with.
func (h *engineImpl) Scan(input []byte) (matches []secrule.MultiRegexEngineMatch, err error) {
	// Use Hyperscan to find the potential matches
	potentialMatches := []int{}
	handler := func(id uint, from, to uint64, flags uint, context interface{}) error {
		potentialMatches = append(potentialMatches, int(id))
		return nil
	}
	err = h.db.Scan(input, h.scratch, handler, nil)
	if err != nil {
		err = fmt.Errorf("failed to invoke Hyperscan: %v", err)
	}

	matches = []secrule.MultiRegexEngineMatch{}

	// Re-validate the potential matches using Go regexp
	for _, pmID := range potentialMatches {
		loc := h.goregexes[pmID].FindIndex(input)
		if loc == nil {
			continue
		}

		m := secrule.MultiRegexEngineMatch{
			ID:       pmID,
			StartPos: loc[0],
			EndPos:   loc[1],
			Data:     input[loc[0]:loc[1]],
		}

		matches = append(matches, m)
	}

	return
}

// Close frees up unmanaged resources. The engine will be unusable after this.
func (h *engineImpl) Close() {
	if h.db != nil {
		h.db.Close()
		h.db = nil
	}

	if h.scratch != nil {
		h.scratch.Free()
		h.scratch = nil
	}
}
