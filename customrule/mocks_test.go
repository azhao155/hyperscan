package customrule

import (
	"azwaf/waf"
	"bytes"
	"io"
)

func newEngineWithCustomRules(rules ...waf.CustomRule) (engine waf.CustomRuleEngine, resLog *mockResultsLogger, err error) {
	geoDB := &mockGeoDB{}
	mref := newMockMultiRegexEngineFactory()
	resLog = newMockResultsLogger()
	cref := NewEngineFactory(mref, geoDB)
	config := &mockCustomRuleConfig{customRules: rules}
	engine, err = cref.NewEngine(config)
	return
}

type mockWafHTTPRequest struct {
	uri        string
	method     string
	remoteAddr string
	headers    []waf.HeaderPair
	configID   string
	body       string
}

func (r *mockWafHTTPRequest) Method() string            { return r.method }
func (r *mockWafHTTPRequest) URI() string               { return r.uri }
func (r *mockWafHTTPRequest) Protocol() string          { return "HTTP/1.1" }
func (r *mockWafHTTPRequest) RemoteAddr() string        { return r.remoteAddr }
func (r *mockWafHTTPRequest) Headers() []waf.HeaderPair { return r.headers }
func (r *mockWafHTTPRequest) ConfigID() string          { return r.configID }
func (r *mockWafHTTPRequest) BodyReader() io.Reader {
	var b bytes.Buffer
	b.WriteString(r.body)
	return &b
}
func (r *mockWafHTTPRequest) LogMetaData() waf.RequestLogMetaData { return &mockLogMetaData{} }
func (r *mockWafHTTPRequest) TransactionID() string               { return "abc" }

type mockHeaderPair struct {
	k string
	v string
}

func (h *mockHeaderPair) Key() string   { return h.k }
func (h *mockHeaderPair) Value() string { return h.v }

type mockLogMetaData struct{}

func (h *mockLogMetaData) Scope() string     { return "Global" }
func (h *mockLogMetaData) ScopeName() string { return "Default Policy" }

type mockGeoDB struct{}

func (mdb *mockGeoDB) PutGeoIPData(geoIPData []waf.GeoIPDataRecord) error { return nil }
func (mdb *mockGeoDB) GeoLookup(ipAddr string) string {
	if ipAddr == "0.0.0.0" {
		return "AA"
	}
	if ipAddr == "1.1.1.1" {
		return "BB"
	}
	if ipAddr == "2.2.2.2" {
		return "CC"
	}
	return ""
}

type mockMatchVariable struct {
	variableName string
	selector     string
}

func (mmvar mockMatchVariable) VariableName() string {
	return mmvar.variableName
}

func (mmvar mockMatchVariable) Selector() string {
	return mmvar.selector
}

type mockMatchCondition struct {
	matchVariables  []waf.MatchVariable
	operator        string
	negateCondition bool
	matchValues     []string
	transforms      []string
}

func (mmc mockMatchCondition) MatchVariables() []waf.MatchVariable {
	return mmc.matchVariables
}

func (mmc mockMatchCondition) Operator() string {
	return mmc.operator
}

func (mmc mockMatchCondition) NegateCondition() bool {
	return mmc.negateCondition
}

func (mmc mockMatchCondition) MatchValues() []string {
	return mmc.matchValues
}

func (mmc mockMatchCondition) Transforms() []string {
	return mmc.transforms
}

type mockCustomRule struct {
	name            string
	priority        int
	ruleType        string
	matchConditions []waf.MatchCondition
	action          string
}

func (mcr mockCustomRule) Name() string {
	return mcr.name
}

func (mcr mockCustomRule) Priority() int {
	return mcr.priority
}

func (mcr mockCustomRule) RuleType() string {
	return mcr.ruleType
}

func (mcr mockCustomRule) MatchConditions() []waf.MatchCondition {
	return mcr.matchConditions
}

func (mcr mockCustomRule) Action() string {
	return mcr.action
}

type mockCustomRuleConfig struct {
	customRules []waf.CustomRule
}

func (mcrc mockCustomRuleConfig) CustomRules() []waf.CustomRule {
	return mcrc.customRules
}

func newMockResultsLogger() *mockResultsLogger {
	return &mockResultsLogger{
		ruleMatched: make(map[string]bool),
		logEntries:  make([]mockResultsLogEntry, 0),
	}
}

type mockResultsLogger struct {
	ruleMatched map[string]bool
	logEntries  []mockResultsLogEntry
}

type mockResultsLogEntry struct {
	ruleID            string
	matchedConditions []waf.ResultsLoggerCustomRulesMatchedConditions
}

func (l *mockResultsLogger) CustomRuleTriggered(customRuleID string, action string, matchedConditions []waf.ResultsLoggerCustomRulesMatchedConditions) {
	l.ruleMatched[customRuleID] = true
	l.logEntries = append(l.logEntries, mockResultsLogEntry{
		ruleID:            customRuleID,
		matchedConditions: matchedConditions,
	})
	return
}

type mockFileSystem struct{}

func (fs *mockFileSystem) ReadFile(name string) (string, error)     { return "", nil }
func (fs *mockFileSystem) WriteFile(name string, json string) error { return nil }
func (fs *mockFileSystem) RemoveFile(name string) error             { return nil }
func (fs *mockFileSystem) ReadDir(name string) ([]string, error)    { return make([]string, 0), nil }
func (fs *mockFileSystem) MkDir(name string) error                  { return nil }

type mockConfigConverter struct{}

func (c *mockConfigConverter) SerializeToJSON(waf.Config) (string, error)         { return "", nil }
func (c *mockConfigConverter) DeserializeFromJSON(str string) (waf.Config, error) { return nil, nil }

func newMockMultiRegexEngineFactory() waf.MultiRegexEngineFactory {
	return &mockMultiRegexEngineFactory{
		newMultiRegexEngineMockFunc: func(mm []waf.MultiRegexEnginePattern) waf.MultiRegexEngine {
			rxIds := make(map[string]int)
			for _, m := range mm {
				rxIds[m.Expr] = m.ID
			}

			return &mockMultiRegexEngine{
				scanMockFunc: func(input []byte) []waf.MultiRegexEngineMatch {
					type preCannedAnswer struct {
						rx   string
						val  string
						data []byte
					}
					preCannedAnswers := []preCannedAnswer{
						{"a", "abe", []byte("abe")},
						{"b", "abe", []byte("abe")},
						{"a", "bart", []byte("bart")},
						{"b", "bart", []byte("bart")},
						{"a", "alice", []byte("alice")},
						{"b", "bob", []byte("bob")},
						{"^true$", "true", []byte("true")},
						{"^john$", "john", []byte("john")},
						{"john", "john", []byte("john")},
						{"john", "firstname=john&lastname=lennon", []byte("john")},
						{"neo", "neo+is+the+one", []byte("neo")},
						{"^DELETE$", "DELETE", []byte("DELETE")},
						{"^/sensitive\\.php", "/sensitive.php?password=12345", []byte("/sensitive.php?password=12345")},
						{"abc", "a=abc", []byte("abc")},
						{"def", "a=def", []byte("def")},
						{"ab+c", "a=abbbc", []byte("abbbc")},
						{"bc$", "a=abc", []byte("bc")},
						{"^a=", "a=abc", []byte("a=")},
						{"ab", "a=abc", []byte("ab")},
						{"^a=abc$", "a=abc", []byte("a=abc")},
						{"abc", "abc", []byte("abc")},
						{"def", "def", []byte("def")},
						{"^abc$", "abc", []byte("abc")},
						{"^ABC$", "ABC", []byte("ABC")},
						{"^ abc $", " abc ", []byte(" abc ")},
						{"^%61%62%63$", "%61%62%63", []byte("%61%62%63")},
						{"^a%20b$", "a%20b", []byte("a%20b")},
						{"^a b$", "a b", []byte("a b")},
						{"^a\x00bc$", "a\x00bc", []byte("a\x00bc")},
						{"^a&#98;c$", "a&#98;c", []byte("a&#98;c")},
						{`^hello world$`, `hello world`, []byte(`hello world`)},
						{`^hello%ggworld$`, `hello%ggworld`, []byte(`hello%ggworld`)},
						{`^hello $`, `hello `, []byte(`hello `)},
						{`^hello%2$`, `hello%2`, []byte(`hello%2`)},
						{`^hello%$`, `hello%`, []byte(`hello%`)},
						{`^ $`, ` `, []byte(` `)},
						{`^%2$`, `%2`, []byte(`%2`)},
						{`^%$`, `%`, []byte(`%`)},
						{`^$`, ``, []byte(``)},
						{"^\x00$", "\x00", []byte("\x00")},
						{`^xjx$`, `xjx`, []byte(`xjx`)},
					}

					r := []waf.MultiRegexEngineMatch{}
					for _, a := range preCannedAnswers {
						if id, ok := rxIds[a.rx]; ok && bytes.Equal(input, []byte(a.val)) {
							r = append(r, waf.MultiRegexEngineMatch{ID: id, Data: a.data})
						}
					}

					return r
				},
			}
		},
	}
}

type mockMultiRegexEngine struct {
	scanMockFunc func(input []byte) []waf.MultiRegexEngineMatch
}

func (m *mockMultiRegexEngine) Scan(input []byte, scratchSpace waf.MultiRegexEngineScratchSpace) (matches []waf.MultiRegexEngineMatch, err error) {
	matches = m.scanMockFunc(input)
	return
}

func (m *mockMultiRegexEngine) CreateScratchSpace() (scratchSpace waf.MultiRegexEngineScratchSpace, err error) {
	return
}

func (m *mockMultiRegexEngine) Close() {
}

type mockMultiRegexEngineFactory struct {
	newMultiRegexEngineMockFunc func(mm []waf.MultiRegexEnginePattern) waf.MultiRegexEngine
}

func (mf *mockMultiRegexEngineFactory) NewMultiRegexEngine(mm []waf.MultiRegexEnginePattern) (m waf.MultiRegexEngine, err error) {
	m = mf.newMultiRegexEngineMockFunc(mm)
	return
}
