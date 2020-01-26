package hyperscan

import (
	"azwaf/waf"
	"testing"

	hs "github.com/flier/gohs/hyperscan"
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

func TestHyperscanStandaloneLatin1(t *testing.T) {
	// Arrange
	patterns := []*hs.Pattern{}
	p := hs.NewPattern("\xbc", 0)
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
	err = db.Scan([]byte("hello \xbc world"), scratch, handler, nil)

	// Assert
	if err != nil {
		t.Fatalf("got unexpected error: %s", err)
	}

	if !found {
		t.Fatalf("Hyperscan DB did not work")
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
}

func TestHyperscanCaptureGroup(t *testing.T) {
	// Arrange
	patterns := []waf.MultiRegexEnginePattern{
		{ID: 1, Expr: `hello(\d+)world`},
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
	r, err := m.Scan([]byte("xyzhello1234worldxyz"), s)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	m.Close()

	// Assert
	if len(r) != 1 {
		t.Fatalf("Got unexpected number of matches: %d", len(r))
	}
	if r[0].ID != 1 {
		t.Fatalf("Unexpected id: %d", r[0].ID)
	}
	if string(r[0].Data) != "hello1234world" {
		t.Fatalf("Unexpected data: %s", string(r[0].Data))
	}
	if len(r[0].CaptureGroups) != 2 {
		t.Fatalf("Unexpected len(r[0].CaptureGroups): %d", len(r[0].CaptureGroups))
	}
	if string(r[0].CaptureGroups[0]) != "hello1234world" {
		t.Fatalf("Unexpected r[0].CaptureGroups[0]: %s", r[0].CaptureGroups[0])
	}
	if string(r[0].CaptureGroups[1]) != "1234" {
		t.Fatalf("Unexpected r[0].CaptureGroups[1]: %s", r[0].CaptureGroups[1])
	}
}

func TestHyperscanNonCaptureGroup(t *testing.T) {
	// Arrange
	patterns := []waf.MultiRegexEnginePattern{
		{ID: 1, Expr: `hello(?:\d+)world`},
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
	r, err := m.Scan([]byte("xyzhello1234worldxyz"), s)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	m.Close()

	// Assert
	if len(r) != 1 {
		t.Fatalf("Got unexpected number of matches: %d", len(r))
	}
	if r[0].ID != 1 {
		t.Fatalf("Unexpected id: %d", r[0].ID)
	}
	if string(r[0].Data) != "hello1234world" {
		t.Fatalf("Unexpected data: %s", string(r[0].Data))
	}
	if len(r[0].CaptureGroups) != 1 {
		t.Fatalf("Unexpected len(r[0].CaptureGroups): %d", len(r[0].CaptureGroups))
	}
	if string(r[0].CaptureGroups[0]) != "hello1234world" {
		t.Fatalf("Unexpected r[0].CaptureGroups[0]: %s", r[0].CaptureGroups[0])
	}
}

func TestHyperscanParenthesis(t *testing.T) {
	// Arrange
	patterns := []waf.MultiRegexEnginePattern{
		{ID: 1, Expr: `hello\(\d+\)world`}, // The parenthesis here are literal parenthesis, not a capture group
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
	r, err := m.Scan([]byte("xyzhello(1234)worldxyz"), s)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	m.Close()

	// Assert
	if len(r) != 1 {
		t.Fatalf("Got unexpected number of matches: %d", len(r))
	}
	if r[0].ID != 1 {
		t.Fatalf("Unexpected id: %d", r[0].ID)
	}
	if string(r[0].Data) != "hello(1234)world" {
		t.Fatalf("Unexpected data: %s", string(r[0].Data))
	}
	if len(r[0].CaptureGroups) != 1 {
		t.Fatalf("Unexpected len(r[0].CaptureGroups): %d", len(r[0].CaptureGroups))
	}
	if string(r[0].CaptureGroups[0]) != "hello(1234)world" {
		t.Fatalf("Unexpected r[0].CaptureGroups[0]: %s", r[0].CaptureGroups[0])
	}
}

func TestHyperscanUtf8(t *testing.T) {
	// Arrange
	patterns := []waf.MultiRegexEnginePattern{
		{ID: 1, Expr: `¼`},
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
	r1, err := m.Scan([]byte("hello ¼ world"), s)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	r2, err := m.Scan([]byte("hello world"), s)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	m.Close()

	// Assert
	if len(r2) != 0 {
		t.Fatalf("Got unexpected number of r2 matches: %d", len(r2))
	}
	if len(r1) != 1 {
		t.Fatalf("Got unexpected number of r1 matches: %d", len(r1))
	}
	if r1[0].ID != 1 {
		t.Fatalf("Unexpected id: %d", r1[0].ID)
	}
	if string(r1[0].Data) != "¼" {
		t.Fatalf("Unexpected data: %s", string(r1[0].Data))
	}
	if len(r1[0].CaptureGroups) != 1 {
		t.Fatalf("Unexpected len(r[0].CaptureGroups): %d", len(r1[0].CaptureGroups))
	}
	if string(r1[0].CaptureGroups[0]) != "¼" {
		t.Fatalf("Unexpected r[0].CaptureGroups[0]: %s", r1[0].CaptureGroups[0])
	}
}

func TestHyperscanPatternBinary(t *testing.T) {
	// Arrange
	// All possible bytes except the printable ASCII range from 0x20 to 0x7E, as some of those will have a special meaning to the regex engine, and we already know printable ASCII works.
	bb := "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x7F\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"
	patterns := []waf.MultiRegexEnginePattern{
		{ID: 1, Expr: "abc" + bb + "def"},
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
	r, err := m.Scan([]byte("xyzabc"+bb+"defxyz"), s)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	m.Close()

	// Assert
	if len(r) != 1 {
		t.Fatalf("Got unexpected number of matches: %d", len(r))
	}
	if r[0].ID != 1 {
		t.Fatalf("Unexpected id: %d", r[0].ID)
	}
	if string(r[0].Data) != "abc"+bb+"def" {
		t.Fatalf("Unexpected data: %s", string(r[0].Data))
	}
	if len(r[0].CaptureGroups) != 1 {
		t.Fatalf("Unexpected len(r[0].CaptureGroups): %d", len(r[0].CaptureGroups))
	}
	if string(r[0].CaptureGroups[0]) != "abc"+bb+"def" {
		t.Fatalf("Unexpected r[0].CaptureGroups[0]: %s", r[0].CaptureGroups[0])
	}
}

func TestHyperscanPatternBinaryEscaped(t *testing.T) {
	// Arrange
	// All possible bytes.
	bb := "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x7B\x7C\x7D\x7E\x7F\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"
	bbRegexEscaped := "\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0A\\x0B\\x0C\\x0D\\x0E\\x0F\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1A\\x1B\\x1C\\x1D\\x1E\\x1F\\x20\\x21\\x22\\x23\\x24\\x25\\x26\\x27\\x28\\x29\\x2A\\x2B\\x2C\\x2D\\x2E\\x2F\\x30\\x31\\x32\\x33\\x34\\x35\\x36\\x37\\x38\\x39\\x3A\\x3B\\x3C\\x3D\\x3E\\x3F\\x40\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\\x49\\x4A\\x4B\\x4C\\x4D\\x4E\\x4F\\x50\\x51\\x52\\x53\\x54\\x55\\x56\\x57\\x58\\x59\\x5A\\x5B\\x5C\\x5D\\x5E\\x5F\\x60\\x61\\x62\\x63\\x64\\x65\\x66\\x67\\x68\\x69\\x6A\\x6B\\x6C\\x6D\\x6E\\x6F\\x70\\x71\\x72\\x73\\x74\\x75\\x76\\x77\\x78\\x79\\x7A\\x7B\\x7C\\x7D\\x7E\\x7F\\x80\\x81\\x82\\x83\\x84\\x85\\x86\\x87\\x88\\x89\\x8A\\x8B\\x8C\\x8D\\x8E\\x8F\\x90\\x91\\x92\\x93\\x94\\x95\\x96\\x97\\x98\\x99\\x9A\\x9B\\x9C\\x9D\\x9E\\x9F\\xA0\\xA1\\xA2\\xA3\\xA4\\xA5\\xA6\\xA7\\xA8\\xA9\\xAA\\xAB\\xAC\\xAD\\xAE\\xAF\\xB0\\xB1\\xB2\\xB3\\xB4\\xB5\\xB6\\xB7\\xB8\\xB9\\xBA\\xBB\\xBC\\xBD\\xBE\\xBF\\xC0\\xC1\\xC2\\xC3\\xC4\\xC5\\xC6\\xC7\\xC8\\xC9\\xCA\\xCB\\xCC\\xCD\\xCE\\xCF\\xD0\\xD1\\xD2\\xD3\\xD4\\xD5\\xD6\\xD7\\xD8\\xD9\\xDA\\xDB\\xDC\\xDD\\xDE\\xDF\\xE0\\xE1\\xE2\\xE3\\xE4\\xE5\\xE6\\xE7\\xE8\\xE9\\xEA\\xEB\\xEC\\xED\\xEE\\xEF\\xF0\\xF1\\xF2\\xF3\\xF4\\xF5\\xF6\\xF7\\xF8\\xF9\\xFA\\xFB\\xFC\\xFD\\xFE\\xFF"
	patterns := []waf.MultiRegexEnginePattern{
		{ID: 1, Expr: "abc" + bbRegexEscaped + "def"},
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
	r, err := m.Scan([]byte("xyzabc"+bb+"defxyz"), s)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
	m.Close()

	// Assert
	if len(r) != 1 {
		t.Fatalf("Got unexpected number of matches: %d", len(r))
	}
	if r[0].ID != 1 {
		t.Fatalf("Unexpected id: %d", r[0].ID)
	}
	if string(r[0].Data) != "abc"+bb+"def" {
		t.Fatalf("Unexpected data: %s", string(r[0].Data))
	}
	if len(r[0].CaptureGroups) != 1 {
		t.Fatalf("Unexpected len(r[0].CaptureGroups): %d", len(r[0].CaptureGroups))
	}
	if string(r[0].CaptureGroups[0]) != "abc"+bb+"def" {
		t.Fatalf("Unexpected r[0].CaptureGroups[0]: %s", r[0].CaptureGroups[0])
	}
}
