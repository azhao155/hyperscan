package logging

import (
	"azwaf/secrule"
	"azwaf/waf"
	"bytes"
	"io"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestSecRuleTriggered(t *testing.T) {

	request := &mockWafHTTPRequest{
		configID: "waf1",
		uri:      "/a",
	}

	stat := &secrule.Rule{
		ID: 11,
	}

	zeroLogger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).Level(1).With().Timestamp().Caller().Logger()
	fileSystem := &mockFileSystem{}
	fileSystem.fmap = make(map[string]LogFile)
	logger1, logger2, _ := NewFileResultsLogger(fileSystem, zeroLogger)

	logger2.SetLogMetaData(&mockConfigLogMetaData{})
	logger1.SecRuleTriggered(request, stat, "deny", "abc", "bce")
	log := fileSystem.Get(Path + FileName)

	expected := `{"resourceId":"appgw","operationName":"ApplicationGatewayFirewall","category":"ApplicationGatewayFirewallLog","properties":{"instanceId":"vm1","clientIp":"","clientPort":"","requestUri":"/a","ruleSetType":"","ruleSetVersion":"","ruleId":"11","ruleGroup":"","message":"abc","action":"deny","details":{"message":"bce","data":"","file":"","line":""},"hostname":"","transactionId":"abc","policyId":"waf1","policyScope":"Global","policyScopeName":"Default Policy"}}`
	if log != expected+"\n" {
		t.Fatalf("SecRuleTriggered get wrong log entry %v, expected %v", log, expected)
	}
}

type mockFile struct {
	Content string
}

func (fs *mockFile) Append(content []byte) (err error) {
	fs.Content = fs.Content + string(content)
	return nil
}

type mockFileSystem struct {
	fmap map[string]LogFile
}

func (fs *mockFileSystem) MkDir(name string) error {
	return nil
}

func (fs *mockFileSystem) Open(name string) (f LogFile, err error) {
	f = &mockFile{}
	fs.fmap[name] = f
	return f, nil
}

func (fs *mockFileSystem) Get(name string) (content string) {
	return fs.fmap[name].(*mockFile).Content
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

type mockLogMetaData struct {
}

func (h *mockLogMetaData) Scope() string     { return "Global" }
func (h *mockLogMetaData) ScopeName() string { return "Default Policy" }

type mockConfigLogMetaData struct {
}

func (h *mockConfigLogMetaData) ResourceID() string { return "appgw" }
func (h *mockConfigLogMetaData) InstanceID() string { return "vm1" }
