package integrationtesting

import (
	"azwaf/secrule"
	"azwaf/waf"
	"bytes"
	"io"
)

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

func (l *mockResultsLogger) FieldBytesLimitExceeded(request waf.ResultsLoggerHTTPRequest, limit int) {}
func (l *mockResultsLogger) PausableBytesLimitExceeded(request waf.ResultsLoggerHTTPRequest, limit int) {
}
func (l *mockResultsLogger) TotalBytesLimitExceeded(request waf.ResultsLoggerHTTPRequest, limit int) {}
func (l *mockResultsLogger) BodyParseError(request waf.ResultsLoggerHTTPRequest, err error)          {}
func (l *mockResultsLogger) SetLogMetaData(metaData waf.ConfigLogMetaData)                           {}

type mockFileSystem struct{}

func (fs *mockFileSystem) ReadFile(name string) (string, error)     { return "", nil }
func (fs *mockFileSystem) WriteFile(name string, json string) error { return nil }
func (fs *mockFileSystem) RemoveFile(name string) error             { return nil }
func (fs *mockFileSystem) ReadDir(name string) ([]string, error)    { return make([]string, 0), nil }
func (fs *mockFileSystem) MkDir(name string) error                  { return nil }

var mockFSFiles = make(map[string][]byte, 0)

type mockGeoDBFileSystem struct{}

func (mfs *mockGeoDBFileSystem) ReadFile(filename string) (buf []byte, err error) {
	if data, ok := mockFSFiles[filename]; ok {
		return data, nil
	}
	return
}

func (mfs *mockGeoDBFileSystem) WriteFile(filename string, buf []byte) error {
	mockFSFiles[filename] = buf
	return nil
}

type mockConfigConverter struct{}

func (c *mockConfigConverter) SerializeToJSON(waf.Config) (string, error)         { return "", nil }
func (c *mockConfigConverter) DeserializeFromJSON(str string) (waf.Config, error) { return nil, nil }

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

type mockGeoIPData struct {
	geoIPDataRecords []waf.GeoIPDataRecord
}

func (m *mockGeoIPData) GeoIPDataRecords() []waf.GeoIPDataRecord { return m.geoIPDataRecords }

type mockGeoIPDataRecord struct {
	startIP     uint32
	endIP       uint32
	countryCode string
}

func (rec *mockGeoIPDataRecord) StartIP() uint32     { return rec.startIP }
func (rec *mockGeoIPDataRecord) EndIP() uint32       { return rec.endIP }
func (rec *mockGeoIPDataRecord) CountryCode() string { return rec.countryCode }

type mockRuleLoaderFileSystem struct{}

func (f *mockRuleLoaderFileSystem) ReadFile(filename string) ([]byte, error) {
	return make([]byte, 0), nil
}
func (f *mockRuleLoaderFileSystem) Abs(path string) (string, error)          { return "", nil }
func (f *mockRuleLoaderFileSystem) EvalSymlinks(path string) (string, error) { return "", nil }

type mockIreFileSystem struct{}

func (mifs *mockIreFileSystem) WriteFile(fileName string, data []byte) error { return nil }
func (mifs *mockIreFileSystem) ReadFile(fileName string) ([]byte, error)     { return nil, nil }
