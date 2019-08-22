package customrule

import (
	"azwaf/waf"
	"io"
)

type mockWafHTTPRequest struct {
	uri        string
	bodyReader io.Reader
	headers    []waf.HeaderPair
}

func (r *mockWafHTTPRequest) Method() string             { return "GET" }
func (r *mockWafHTTPRequest) URI() string                { return r.uri }
func (r *mockWafHTTPRequest) ConfigID() string           { return "SecRuleConfig1" }
func (r *mockWafHTTPRequest) CustomRuleConfigID() string { return "CustomRuleConfig1" }
func (r *mockWafHTTPRequest) Headers() []waf.HeaderPair  { return r.headers }
func (r *mockWafHTTPRequest) BodyReader() io.Reader      { return r.bodyReader }

type mockHeaderPair struct {
	k string
	v string
}

func (h *mockHeaderPair) Key() string   { return h.k }
func (h *mockHeaderPair) Value() string { return h.v }
