package waf

import (
	"azwaf/testutils"
	"bytes"
	"github.com/rs/zerolog"
	"io"
	"testing"
)

func TestWafServerEvalRequest(t *testing.T) {
	// Arrange
	logger := testutils.NewTestLogger(t)
	msre := &mockSecRuleEngine{}
	msref := &mockSecRuleEngineFactory{msre: msre}
	c := make(map[int64]Config)
	c[0] = &mockConfig{}
	s, err := NewServer(logger, c, msref)
	if err != nil {
		t.Fatalf("Error from NewServer: %s", err)
	}
	req := &mockWafHTTPRequest{}

	// Act
	s.EvalRequest(req)

	// Assert
	if msref.newEngineCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockSecRuleEngineFactory.NewEngine")
	}

	if msre.evalRequestCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockSecRuleEngine.EvalRequest")
	}
}

type mockSecRuleEngine struct {
	evalRequestCalled int
}

func (m *mockSecRuleEngine) EvalRequest(logger zerolog.Logger, req HTTPRequest) bool {
	m.evalRequestCalled++
	return true
}

type mockSecRuleEngineFactory struct {
	msre            *mockSecRuleEngine
	newEngineCalled int
}

func (m *mockSecRuleEngineFactory) NewEngine(c SecRuleConfig) (engine SecRuleEngine, err error) {
	m.newEngineCalled++
	engine = m.msre
	return
}

type mockWafHTTPRequest struct{}

func (r *mockWafHTTPRequest) Method() string        { return "GET" }
func (r *mockWafHTTPRequest) URI() string           { return "/hello.php?arg1=aaaaaaabccc" }
func (r *mockWafHTTPRequest) Headers() []HeaderPair { return nil }
func (r *mockWafHTTPRequest) RuleSetID() string     { return "SecRuleConfig1" }
func (r *mockWafHTTPRequest) Version() int64        { return 0 }
func (r *mockWafHTTPRequest) BodyReader() io.Reader { return &bytes.Buffer{} }
