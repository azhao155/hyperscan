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
	req := &mockWafHTTPRequest{uri: "http://localhost:8080/", method: "GET"}

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
