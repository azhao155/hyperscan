package waf

import (
	"azwaf/config"
	pb "azwaf/proto"
	"azwaf/secrule"

	"testing"
)

type mockSecRuleEngine struct {
	evalRequestCalled int
}

func (m *mockSecRuleEngine) EvalRequest(req *pb.WafHttpRequest) bool {
	m.evalRequestCalled++
	return true
}

type mockSecRuleEngineFactory struct {
	msre             *mockSecRuleEngine
	newEnginetCalled int
}

func (m *mockSecRuleEngineFactory) NewEngine(siteName string) secrule.Engine {
	m.newEnginetCalled++
	return m.msre
}

func TestWafServerEvalRequest(t *testing.T) {
	// Arrange
	c := &config.Main{Sites: []config.Site{config.Site{Name: "site1"}}}
	msre := &mockSecRuleEngine{}
	msref := &mockSecRuleEngineFactory{msre: msre}
	s := NewServer(c, msref)
	req := &pb.WafHttpRequest{}

	// Act
	s.EvalRequest(req)

	// Assert
	if msref.newEnginetCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockSecRuleEngineFactory.NewEngine")
	}

	if msre.evalRequestCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockSecRuleEngine.EvalRequest")
	}
}
