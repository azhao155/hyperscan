package waf

import (
	"azwaf/config"
	pb "azwaf/proto"
	"azwaf/secrule"

	"testing"
)

func TestWafServerEvalRequest(t *testing.T) {
	// Arrange
	c := &config.Main{Sites: []config.Site{{Name: "site1", RuleSet: "OWASP CRS 3.0"}}}
	msre := &mockSecRuleEngine{}
	msref := &mockSecRuleEngineFactory{msre: msre}
	s, err := NewServer(c, msref)
	if err != nil {
		t.Fatalf("Error from NewServer: %s", err)
	}
	req := &pb.WafHttpRequest{Uri: "/hello.php?arg1=aaaaaaabccc"}

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

func (m *mockSecRuleEngine) EvalRequest(req *pb.WafHttpRequest) bool {
	m.evalRequestCalled++
	return true
}

type mockSecRuleEngineFactory struct {
	msre            *mockSecRuleEngine
	newEngineCalled int
}

func (m *mockSecRuleEngineFactory) NewEngine(r secrule.RuleSetID) (engine secrule.Engine, err error) {
	m.newEngineCalled++
	engine = m.msre
	return
}
