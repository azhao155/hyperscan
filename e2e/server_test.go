package e2e

import (
	"azwaf/grpc"
	"azwaf/waf"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func startServer(t *testing.T) {
	// Remove socket file if it exists
	sockAddr := "/tmp/azwaf.sock"
	if err := os.RemoveAll(sockAddr); err != nil {
		t.Fatal(err)
	}
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).Level(zerolog.ErrorLevel).With().Timestamp().Caller().Logger()
	go grpc.StartServer(logger, "", waf.DefaultLengthLimits, false, "unix", sockAddr, nil)
}
