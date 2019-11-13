package hyperscan

import (
	"azwaf/waf"
	"fmt"
	hs "github.com/flier/gohs/hyperscan"
	"regexp"
)

type engineFactoryImpl struct {
	dbCache DbCache
}

type engineImpl struct {
	// Hyperscan's compiled database of regexes.
	db hs.BlockDatabase

	// Precompiled Go regexes used to re-validate matches.
	goregexes map[int]*regexp.Regexp // TODO could this have been just a list rather than map?

	// Special case for when searching for an empty string, because Hyperscan returns an error if it's given an empty string
	emptyStringPatternIDs []int
}

type scratchSpaceImpl struct {
	// Pre-allocated memory space that Hyperscan needs during evaluation.
	scratch *hs.Scratch

	// Scratch spaces are specifically allocated to work for just one Hyperscan DB.
	belongsTo *engineImpl
}

// NewMultiRegexEngineFactory creates a MultiRegexEngineFactory which will create Hyperscan based MultiRegexEngines. DbCache is used to speed up initializing databases that was previously already built. This can be nil if you do not want to use a cache.
func NewMultiRegexEngineFactory(dbCache DbCache) waf.MultiRegexEngineFactory {
	return &engineFactoryImpl{dbCache: dbCache}
}

// NewMultiRegexEngine creates a MultiRegexEngine that uses Hyperscan in prefilter mode for the initial scan, and then uses Go regexp to re-validate matches and extract strings.
func (f *engineFactoryImpl) NewMultiRegexEngine(mm []waf.MultiRegexEnginePattern) (engine waf.MultiRegexEngine, err error) {
	h := &engineImpl{}

	patterns := []*hs.Pattern{}
	for _, m := range mm {
		// Special case for when searching for an empty string, because Hyperscan returns an error if it's given an empty string
		if m.Expr == "^$" {
			h.emptyStringPatternIDs = append(h.emptyStringPatternIDs, m.ID)
			continue
		}

		p := hs.NewPattern(m.Expr, 0)
		p.Id = m.ID

		// SingleMatch makes Hyperscan only return one match per regex. So if a regex is found multiple time, still only one match is recorded.
		// PrefilterMode gives broader regex compatibility, at the cost possible false positives. Potential matches therefore must be verified with another regex engine.
		p.Flags = hs.SingleMatch | hs.PrefilterMode

		patterns = append(patterns, p)
	}

	if len(patterns) == 0 {
		engine = h
		return
	}

	// Try to load precompiled database from cache.
	var cacheID string
	if f.dbCache != nil {
		cacheID = f.dbCache.cacheID(patterns)
		h.db = f.dbCache.loadFromCache(cacheID)
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
func (h *engineImpl) Scan(input []byte, s waf.MultiRegexEngineScratchSpace) (matches []waf.MultiRegexEngineMatch, err error) {
	scratchSpace, valid := s.(*scratchSpaceImpl)
	if !valid || scratchSpace.belongsTo != h {
		panic("scratch spaces can only be used with the Hyperscan DB they were initialized for.")
	}

	matches = []waf.MultiRegexEngineMatch{}

	// Special case for when searching for an empty string, because Hyperscan returns an error if it's given an empty string
	if len(input) == 0 {
		for _, ID := range h.emptyStringPatternIDs {
			m := waf.MultiRegexEngineMatch{ID: ID}
			matches = append(matches, m)
		}
		return
	}

	if h.db == nil {
		if len(h.goregexes) > 0 {
			panic("multi regex engine in inconsistent state. Hyperscan DB was nil but there were Go regexes.")
		}
		return
	}

	// Use Hyperscan to find the potential matches
	potentialMatches := []int{}
	handler := func(id uint, from, to uint64, flags uint, context interface{}) error {
		potentialMatches = append(potentialMatches, int(id))
		return nil
	}
	err = h.db.Scan(input, scratchSpace.scratch, handler, nil)
	if err != nil {
		err = fmt.Errorf("failed to invoke Hyperscan: %v", err)
	}

	// Re-validate the potential matches using Go regexp
	for _, pmID := range potentialMatches {
		loc := h.goregexes[pmID].FindSubmatchIndex(input)
		if loc == nil {
			continue
		}

		// FindSubmatchIndex will always return an even number, because it returns pairs of start-end-locations.
		var captureGroups [][]byte
		for i := 0; i < len(loc); i = i + 2 {
			if loc[i] != -1 {
				captureGroups = append(captureGroups, input[loc[i]:loc[i+1]])
			} else {
				// This capture group was not found
				captureGroups = append(captureGroups, []byte{})
			}
		}

		m := waf.MultiRegexEngineMatch{
			ID:            pmID,
			StartPos:      loc[0],
			EndPos:        loc[1],
			Data:          input[loc[0]:loc[1]],
			CaptureGroups: captureGroups,
		}

		matches = append(matches, m)
	}

	return
}

func (h *engineImpl) CreateScratchSpace() (scratchSpace waf.MultiRegexEngineScratchSpace, err error) {
	s := &scratchSpaceImpl{belongsTo: h}

	if h.db == nil {
		// This happens if this is a multi regex engine with zero patterns.
		scratchSpace = s
		return
	}

	s.scratch, err = hs.NewScratch(h.db)
	if err != nil {
		scratchSpace.Close()
		err = fmt.Errorf("failed to create Hyperscan scratch space: %v", err)
		return
	}

	scratchSpace = s
	return
}

// Close frees up unmanaged resources. The engine will be unusable after this.
func (h *engineImpl) Close() {
	if h.db != nil {
		h.db.Close()
		h.db = nil
	}
}

// Close frees up unmanaged resources. The scratch space will be unusable after this.
func (s *scratchSpaceImpl) Close() {
	if s.scratch != nil {
		s.scratch.Free()
		s.scratch = nil
	}
}
