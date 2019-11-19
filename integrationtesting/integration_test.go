package integrationtesting

import (
	"azwaf/waf"
	"testing"

	"github.com/rs/zerolog"
)

func TestNewStandaloneSecruleServerEvalRequestCrs30(t *testing.T) {
	origLogLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	defer zerolog.SetGlobalLevel(origLogLevel)

	// Arrange
	wafServer := newTestStandaloneSecruleServer(t)
	headers := []waf.HeaderPair{&mockHeaderPair{k: "Host", v: "example.com"}}
	req1 := &mockWafHTTPRequest{uri: "http://localhost:8080/?a=hello", method: "GET", headers: headers}
	req2 := &mockWafHTTPRequest{uri: "http://localhost:8080/?a=/etc/passwd", method: "GET", headers: headers}

	// Act
	decision1, err := wafServer.EvalRequest(req1)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	decision2, err := wafServer.EvalRequest(req2)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Assert
	if decision1 != waf.Pass {
		t.Fatalf("EvalRequest did not return pass")
	}
	if decision2 != waf.Block {
		t.Fatalf("EvalRequest did not return block")
	}
}
