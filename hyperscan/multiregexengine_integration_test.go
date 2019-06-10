package hyperscan

import (
	"azwaf/secrule"
	"testing"
)

func TestHyperscanSimple(t *testing.T) {
	// Arrange
	patterns := []secrule.MultiRegexEnginePattern{
		{ID: 0, Expr: "a+bc"},
		{ID: 1, Expr: "ab+c"},
		{ID: 2, Expr: "abc+"},
	}

	// Act
	f := NewMultiRegexEngineFactory()
	m, err := f.NewMultiRegexEngine(patterns)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	r, err := m.Scan([]byte("xyzabbbbcxyz"))
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Assert
	if len(r) != 1 {
		t.Fatalf("Got unexpected number of matches: %d", len(r))
	}

	if r[0].ID != 1 {
		t.Fatalf("Unexpected id: %d", r[0].ID)
	}

	if r[0].EndPos != 9 {
		t.Fatalf("Unexpected to: %d", r[0].EndPos)
	}
}
