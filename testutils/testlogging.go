package testutils

import (
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// NewTestLogger creates a zerolog.Logger that writes to testing.T's log.
func NewTestLogger(t *testing.T) zerolog.Logger {
	return zerolog.New(zerolog.ConsoleWriter{Out: testWriter{t}, TimeFormat: time.RFC3339, NoColor: true}).With().Timestamp().Caller().Logger()
}

type testWriter struct {
	t *testing.T
}

func (tw testWriter) Write(p []byte) (n int, err error) {
	tw.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}
