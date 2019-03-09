package secrule

// EngineFactory creates a secrule.Engine. This makes mocking possible when testing.
type EngineFactory interface {
	NewEngine(sitename string) Engine
}

type engineFactory struct {
}

func (s *engineFactory) NewEngine(siteName string) Engine {
	return &engineImpl{siteName}
}

// NewEngineFactory creates a secrule.EngineFactory.
func NewEngineFactory() EngineFactory {
	return &engineFactory{}
}
