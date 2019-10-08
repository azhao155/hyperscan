package customrule

import (
	"azwaf/hyperscan"
	"azwaf/secrule"
	"azwaf/waf"
	"bytes"
	"io"

	"github.com/rs/zerolog"
)

func newEngineWithCustomRules(logger zerolog.Logger, rules ...waf.CustomRule) (waf.CustomRuleEngine, error) {
	crl := NewCustomRuleLoader(&mockGeoDB{})

	// Need a fully functional secrule engine to properly test custom rules.
	hsfs := hyperscan.NewCacheFileSystem()
	hscache := hyperscan.NewDbCache(hsfs)
	mref := hyperscan.NewMultiRegexEngineFactory(hscache)
	rsf := secrule.NewReqScannerFactory(mref)
	re := secrule.NewRuleEvaluator()

	cref := NewEngineFactory(logger, crl, rsf, re)

	config := &mockCustomRuleConfig{customRules: rules}
	return cref.NewEngine(config)
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
func (mdb *mockGeoDB) GeoLookup(ipAddr string) string                     { return "CC" }

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

type mockResultsLogger struct {
	ruleMatched map[int]bool
}

func (l *mockResultsLogger) SecRuleTriggered(request secrule.ResultsLoggerHTTPRequest, stmt secrule.Statement, action string, msg string, logData string) {
	r, ok := stmt.(*secrule.Rule)
	if ok {
		l.ruleMatched[r.ID] = true
	}
	return
}

func (l *mockResultsLogger) FieldBytesLimitExceeded(request waf.ResultsLoggerHTTPRequest, limit int) {
}
func (l *mockResultsLogger) PausableBytesLimitExceeded(request waf.ResultsLoggerHTTPRequest, limit int) {
}
func (l *mockResultsLogger) TotalBytesLimitExceeded(request waf.ResultsLoggerHTTPRequest, limit int) {
}
func (l *mockResultsLogger) BodyParseError(request waf.ResultsLoggerHTTPRequest, err error) {
}
func (l *mockResultsLogger) SetLogMetaData(metaData waf.ConfigLogMetaData) {
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
