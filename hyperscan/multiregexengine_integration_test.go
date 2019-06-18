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
	m.Close()
	m.Close() // Ensure that it doesn't fail on second close

	// Assert
	if len(r) != 1 {
		t.Fatalf("Got unexpected number of matches: %d", len(r))
	}
	if r[0].ID != 1 {
		t.Fatalf("Unexpected id: %d", r[0].ID)
	}
	if string(r[0].Data) != "abbbbc" {
		t.Fatalf("Unexpected data: %s", string(r[0].Data))
	}
	if r[0].StartPos != 3 {
		t.Fatalf("Unexpected StartPos: %d", r[0].EndPos)
	}
	if r[0].EndPos != 9 {
		t.Fatalf("Unexpected endPos: %d", r[0].EndPos)
	}
}

func TestHyperscanSimpleTwoScans(t *testing.T) {
	// Arrange
	f := NewMultiRegexEngineFactory()
	e, err := f.NewMultiRegexEngine([]secrule.MultiRegexEnginePattern{
		{ID: 1, Expr: "ab+"},
		{ID: 2, Expr: "ac+"},
	})
	if err != nil {
		t.Fatalf("%s", err)
	}

	// Act
	m, err := e.Scan([]byte("abbbbcccccc"))

	// Assert
	if err != nil {
		t.Fatalf("%s", err)
	}
	if len(m) != 1 {
		t.Fatalf("Scan 1, unexpected count of matches: %d", len(m))
	}
	if m[0].ID != 1 {
		t.Fatalf("Scan 1, unexpected match ID: %d", m[0].ID)
	}
	if m[0].StartPos != 0 {
		t.Fatalf("Scan 1, unexpected match StartPos: %d", m[0].StartPos)
	}
	if m[0].EndPos != 5 {
		t.Fatalf("Scan 1, unexpected match EndPos: %d", m[0].EndPos)
	}
	if string(m[0].Data) != "abbbb" {
		t.Fatalf("Scan 2, unexpected match data: %s", string(m[0].Data))
	}

	// Act
	m, err = e.Scan([]byte("xxxaaaaccccccbbbb"))

	// Assert
	if err != nil {
		t.Fatalf("%s", err)
	}
	if len(m) != 1 {
		t.Fatalf("Scan 2, unexpected count of matches: %d", len(m))
	}
	if m[0].ID != 2 {
		t.Fatalf("Scan 2, unexpected match ID: %d", m[0].ID)
	}
	if m[0].StartPos != 6 {
		t.Fatalf("Scan 1, unexpected match StartPos: %d", m[0].StartPos)
	}
	if m[0].EndPos != 13 {
		t.Fatalf("Scan 2, unexpected match EndPos: %d", m[0].EndPos)
	}
	if string(m[0].Data) != "acccccc" {
		t.Fatalf("Scan 2, unexpected match data: %s", string(m[0].Data))
	}

	e.Close()
}

func TestExpressionWithPCREPossessiveQuantifier(t *testing.T) {
	// Arrange
	patterns := []secrule.MultiRegexEnginePattern{
		{ID: 0, Expr: "a++bc"},
	}

	// Act
	f := NewMultiRegexEngineFactory()
	m, err := f.NewMultiRegexEngine(patterns)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	r, err := m.Scan([]byte("xyzaaabcxyz"))
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	m.Close()

	// Assert
	if len(r) != 1 {
		t.Fatalf("Got unexpected number of matches: %d", len(r))
	}

	if r[0].ID != 0 {
		t.Fatalf("Unexpected id: %d", r[0].ID)
	}

	if string(r[0].Data) != "aaabc" {
		t.Fatalf("Unexpected data: %s", string(r[0].Data))
	}

	if r[0].StartPos != 3 {
		t.Fatalf("Unexpected StartPos: %d", r[0].StartPos)
	}

	if r[0].EndPos != 8 {
		t.Fatalf("Unexpected EndPos: %d", r[0].EndPos)
	}
}
