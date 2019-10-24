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
	req := &mockWafHTTPRequest{uri: "http://localhost:8080/", method: "GET", headers: headers}

	// Act
	decision, err := wafServer.EvalRequest(req)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Assert
	if decision != waf.Pass {
		t.Fatalf("EvalRequest did not return pass")
	}
}
