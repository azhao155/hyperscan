package waf

// MultiRegexEngineFactory is an interface to a factory that can create regex engines that can scan for multiple regexes at once that we will depend on, such as HyperScan or RE2::Set.
type MultiRegexEngineFactory interface {
	NewMultiRegexEngine(mm []MultiRegexEnginePattern) (m MultiRegexEngine, err error)
}

// MultiRegexEngine is an interface to a regex engine that can scan for multiple regexes at once.
type MultiRegexEngine interface {
	Scan(input []byte, scratchSpace MultiRegexEngineScratchSpace) (matches []MultiRegexEngineMatch, err error)
	CreateScratchSpace() (scratchSpace MultiRegexEngineScratchSpace, err error)
	Close()
}

// MultiRegexEnginePattern is used by the MultiRegexEngineFactory to tell it what to scan for.
type MultiRegexEnginePattern struct {
	ID   int
	Expr string
}

// MultiRegexEngineMatch is used by the MultiRegexEngine interface to communicate back which matches were found.
type MultiRegexEngineMatch struct {
	ID            int
	Data          []byte
	CaptureGroups [][]byte
}

// MultiRegexEngineScratchSpace is temporary memory needed by a MultiRegexEngine, which may not be concurrently used.
type MultiRegexEngineScratchSpace interface {
	Close()
}
