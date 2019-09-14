package integrationtesting

import (
	"azwaf/waf"
	"bytes"
	"io"
)

type mockWafHTTPRequest struct {
	uri        string
	method     string
	headers    []waf.HeaderPair
	configID   string
	body       string
	remoteAddr string
}

func (r *mockWafHTTPRequest) Method() string            { return r.method }
func (r *mockWafHTTPRequest) URI() string               { return r.uri }
func (r *mockWafHTTPRequest) Headers() []waf.HeaderPair { return r.headers }
func (r *mockWafHTTPRequest) ConfigID() string          { return r.configID }
func (r *mockWafHTTPRequest) BodyReader() io.Reader {
	var b bytes.Buffer
	b.WriteString(r.body)
	return &b
}
func (r *mockWafHTTPRequest) LogMetaData() waf.RequestLogMetaData { return &mockLogMetaData{} }
func (r *mockWafHTTPRequest) TransactionID() string               { return "abc" }
func (r *mockWafHTTPRequest) RemoteAddr() string                  { return "0.0.0.0" }

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
