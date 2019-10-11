package hyperscan

import (
	"azwaf/waf"
	hs "github.com/flier/gohs/hyperscan"
	"testing"
)

func TestHyperscanStandalone(t *testing.T) {
	// Arrange
	patterns := []*hs.Pattern{}
	p := hs.NewPattern("abc+", 0)
	p.Id = 100
	p.Flags = hs.SingleMatch | hs.PrefilterMode
	patterns = append(patterns, p)
	db, err := hs.NewBlockDatabase(patterns...)
	if err != nil {
		t.Fatalf("got unexpected error: %s", err)
	}
	scratch, err := hs.NewScratch(db)
	if err != nil {
		db.Close()
		t.Fatalf("failed to create Hyperscan scratch space: %v", err)
	}

	// Act
	found := false
	handler := func(id uint, from, to uint64, flags uint, context interface{}) error {
		if id == 100 {
			found = true
		}
		return nil
	}
	err = db.Scan([]byte("abcccc"), scratch, handler, nil)

	// Assert
	if err != nil {
		t.Fatalf("got unexpected error: %s", err)
	}

	if !found {
		t.Fatalf("Hyperscan DB did not work")
	}

	db.Close()
}

func TestHyperscanStandaloneEmptyStringBehaviour(t *testing.T) {
	// Arrange
	patterns := []*hs.Pattern{}
	p := hs.NewPattern(".+", 0)
	p.Id = 100
	p.Flags = hs.SingleMatch | hs.PrefilterMode
	patterns = append(patterns, p)
	db, err := hs.NewBlockDatabase(patterns...)
	if err != nil {
		t.Fatalf("got unexpected error: %s", err)
	}
	scratch, err := hs.NewScratch(db)
	if err != nil {
		db.Close()
		t.Fatalf("failed to create Hyperscan scratch space: %v", err)
	}

	// Act
	handler := func(id uint, from, to uint64, flags uint, context interface{}) error {
		return nil
	}
	err = db.Scan([]byte(""), scratch, handler, nil)

	// Assert
	if err == nil {
		t.Fatalf("Expected error but got nil")
	}

	// This is not a cool way to react on an empty string on Hyperscan's part, but it is what it is...
	if err.Error() != "A parameter passed to this function was invalid." {
		t.Fatalf("Unexpected error: %v", err.Error())
	}

	db.Close()
}

func TestHyperscanSimple(t *testing.T) {
	// Arrange
	patterns := []waf.MultiRegexEnginePattern{
		{ID: 0, Expr: "a+bc"},
		{ID: 1, Expr: "ab+c"},
		{ID: 2, Expr: "abc+"},
	}

	// Act
	f := NewMultiRegexEngineFactory(nil)
	m, err := f.NewMultiRegexEngine(patterns)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	s, err := m.CreateScratchSpace()
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	r, err := m.Scan([]byte("xyzabbbbcxyz"), s)
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
	f := NewMultiRegexEngineFactory(nil)
	e, err := f.NewMultiRegexEngine([]waf.MultiRegexEnginePattern{
		{ID: 1, Expr: "ab+"},
		{ID: 2, Expr: "ac+"},
	})
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	s, err := e.CreateScratchSpace()
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Act
	m, err := e.Scan([]byte("abbbbcccccc"), s)

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
	m, err = e.Scan([]byte("xxxaaaaccccccbbbb"), s)

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
	patterns := []waf.MultiRegexEnginePattern{
		{ID: 0, Expr: "a++bc"},
	}

	// Act
	f := NewMultiRegexEngineFactory(nil)
	m, err := f.NewMultiRegexEngine(patterns)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	s, err := m.CreateScratchSpace()
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	r, err := m.Scan([]byte("xyzaaabcxyz"), s)
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

func TestHyperscanEmptyString(t *testing.T) {
	// Arrange
	patterns := []waf.MultiRegexEnginePattern{
		{ID: 100, Expr: "^$"},
	}

	// Act
	f := NewMultiRegexEngineFactory(nil)
	m, err := f.NewMultiRegexEngine(patterns)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	s, err := m.CreateScratchSpace()
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	r, err := m.Scan([]byte(""), s)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	m.Close()
	m.Close() // Ensure that it doesn't fail on second close

	// Assert
	if len(r) != 1 {
		t.Fatalf("Got unexpected number of matches: %d", len(r))
	}
	if r[0].ID != 100 {
		t.Fatalf("Unexpected id: %d", r[0].ID)
	}
	if string(r[0].Data) != "" {
		t.Fatalf("Unexpected data: %s", string(r[0].Data))
	}
	if r[0].StartPos != 0 {
		t.Fatalf("Unexpected StartPos: %d", r[0].EndPos)
	}
	if r[0].EndPos != 0 {
		t.Fatalf("Unexpected endPos: %d", r[0].EndPos)
	}
}
