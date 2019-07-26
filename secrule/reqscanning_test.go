package secrule

import (
	"azwaf/waf"
	"io"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReqScanner1(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules, _ := newMockRuleLoader().Rules("some ruleset")
	req := &mockWafHTTPRequest{uri: "/hello.php?arg1=aaaaaaabccc"}

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	sr, err2 := rs.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	m, ok := sr.GetRxResultsFor(300, 0, "REQUEST_URI_RAW")
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "aaaaaaabc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
	if m.StartPos != 16 {
		t.Fatalf("Unexpected match pos: %d", m.StartPos)
	}
	if m.EndPos != 25 {
		t.Fatalf("Unexpected match pos: %d", m.EndPos)
	}

	m, ok = sr.GetRxResultsFor(200, 0, "ARGS")
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "abccc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
	if m.StartPos != 6 {
		t.Fatalf("Unexpected match pos: %d", m.StartPos)
	}
	if m.EndPos != 11 {
		t.Fatalf("Unexpected match pos: %d", m.EndPos)
	}

	m, ok = sr.GetRxResultsFor(200, 1, "ARGS")
	if ok {
		t.Fatalf("Unexpected match found")
	}
}

func TestGetExprsRx(t *testing.T) {
	r1 := &RuleItem{Predicate: RulePredicate{Op: Rx, Val: "abc+"}}
	ee := getRxExprs(r1)
	if ee == nil {
		t.Fatalf("Expressions should not be nil")
	}

	if len(ee) != 1 {
		t.Fatalf("Unexpected expression count %d", len(ee))
	}

	if ee[0] != "abc+" {
		t.Fatalf("Invalid expression %s", ee[0])
	}
}

func TestGetExprsLiteralValueUnicode(t *testing.T) {
	assert := assert.New(t)
	r1 := &RuleItem{Predicate: RulePredicate{Op: BeginsWith, Val: "你好"}}
	ee := getRxExprs(r1)
	assert.NotNil(ee)
	assert.Equal("^你好", ee[0])
	re := regexp.MustCompile(ee[0])
	assert.True(re.MatchString("你好d"))
	assert.False(re.MatchString("d^你好d"))
}

func TestGetExprsBeginsWith(t *testing.T) {
	assert := assert.New(t)
	r1 := &RuleItem{Predicate: RulePredicate{Op: BeginsWith, Val: "^abc"}}
	ee := getRxExprs(r1)
	assert.NotNil(ee)
	assert.Equal("^\\^abc", ee[0])
	re := regexp.MustCompile(ee[0])
	assert.True(re.MatchString("^abcd"))
	assert.False(re.MatchString("dabcd"))
}

func TestGetExprsEndsWith(t *testing.T) {
	assert := assert.New(t)
	r1 := &RuleItem{Predicate: RulePredicate{Op: EndsWith, Val: "$abc"}}
	ee := getRxExprs(r1)
	assert.NotNil(ee)
	assert.Equal("\\$abc$", ee[0])
	re := regexp.MustCompile(ee[0])
	assert.True(re.MatchString("d$abc"))
	assert.False(re.MatchString("abcd"))
}

func TestGetExprsContains(t *testing.T) {
	assert := assert.New(t)
	r1 := &RuleItem{Predicate: RulePredicate{Op: Contains, Val: "a b.c"}}
	ee := getRxExprs(r1)
	assert.NotNil(ee)
	assert.Equal("a b\\.c", ee[0])
	re := regexp.MustCompile(ee[0])
	assert.True(re.MatchString("da b.c"))
	assert.False(re.MatchString("ab cd"))
}

func TestGetExprsStrmatch(t *testing.T) {
	assert := assert.New(t)
	r1 := &RuleItem{Predicate: RulePredicate{Op: Strmatch, Val: "a b.c"}}
	ee := getRxExprs(r1)
	assert.NotNil(ee)
	assert.Equal("a b\\.c", ee[0])
	re := regexp.MustCompile(ee[0])
	assert.True(re.MatchString("da b.c"))
	assert.False(re.MatchString("ab cd"))
}

func TestGetExprsContainsWord(t *testing.T) {
	assert := assert.New(t)
	r1 := &RuleItem{Predicate: RulePredicate{Op: ContainsWord, Val: "a$bc"}}
	ee := getRxExprs(r1)
	assert.NotNil(ee)
	assert.Equal("\\ba\\$bc\\b", ee[0])
	re := regexp.MustCompile(ee[0])
	assert.True(re.MatchString(" a$bc "))
	assert.True(re.MatchString(" a$bc"))
	assert.True(re.MatchString(" a$bc\n"))
	assert.False(re.MatchString("a$bcd"))
}

func TestGetExprsStreq(t *testing.T) {
	assert := assert.New(t)
	r1 := &RuleItem{Predicate: RulePredicate{Op: Streq, Val: "a$bc"}}
	ee := getRxExprs(r1)
	assert.NotNil(ee)
	assert.Equal("^a\\$bc$", ee[0])
	re := regexp.MustCompile(ee[0])
	assert.True(re.MatchString("a$bc"))
	assert.False(re.MatchString("a$bcd"))
}

func TestGetExprsWithin(t *testing.T) {
	assert := assert.New(t)
	r1 := &RuleItem{Predicate: RulePredicate{Op: Within, Val: "abc$ def ghi"}}
	ee := getRxExprs(r1)
	assert.NotNil(ee)
	assert.Equal("^abc\\$$", ee[0])
	re := regexp.MustCompile(ee[0])
	assert.True(re.MatchString("abc$"))
	assert.False(re.MatchString("abc$d"))
}

func TestGetExprsPmf(t *testing.T) {
	r1 := &RuleItem{Predicate: RulePredicate{Op: Pmf}, PmPhrases: []string{"abc", "def"}}
	ee := getRxExprs(r1)
	if ee == nil {
		t.Fatalf("Expressions should not be nil")
	}

	if len(ee) != 2 {
		t.Fatalf("Unexpected expression count %d", len(ee))
	}

	if ee[0] != "abc" {
		t.Fatalf("Invalid expression %s", ee[0])
	}

	if ee[1] != "def" {
		t.Fatalf("Invalid expression %s", ee[1])
	}
}

func TestReqScannerBodyField(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules, _ := newMockRuleLoader().Rules("some ruleset")
	req := &mockWafHTTPRequest{uri: "/hello.php"}

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	sr, err2 := rs.ScanHeaders(req)
	err3 := rs.ScanBodyField(waf.URLEncodedContent, "arg1", "aaaaaaabccc", sr)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	if err3 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	m, ok := sr.GetRxResultsFor(300, 0, "REQUEST_URI_RAW")
	if ok {
		t.Fatalf("Unexpected match found")
	}

	m, ok = sr.GetRxResultsFor(200, 0, "ARGS")
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "abccc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
	if m.StartPos != 6 {
		t.Fatalf("Unexpected match pos: %d", m.StartPos)
	}
	if m.EndPos != 11 {
		t.Fatalf("Unexpected match pos: %d", m.EndPos)
	}

	m, ok = sr.GetRxResultsFor(200, 1, "ARGS")
	if ok {
		t.Fatalf("Unexpected match found")
	}
}

type mockWafHTTPRequest struct {
	uri        string
	bodyReader io.Reader
	headers    []waf.HeaderPair
}

func (r *mockWafHTTPRequest) Method() string            { return "GET" }
func (r *mockWafHTTPRequest) URI() string               { return r.uri }
func (r *mockWafHTTPRequest) SecRuleConfigID() string   { return "SecRuleConfig1" }
func (r *mockWafHTTPRequest) Headers() []waf.HeaderPair { return r.headers }
func (r *mockWafHTTPRequest) BodyReader() io.Reader     { return r.bodyReader }

type mockHeaderPair struct {
	k string
	v string
}

func (h *mockHeaderPair) Key() string   { return h.k }
func (h *mockHeaderPair) Value() string { return h.v }
