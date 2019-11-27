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
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	if sr.targetsCount[Target{Name: "REQUEST_URI_RAW"}] == 0 {
		t.Fatalf("Target REQUEST_URI_RAW not present")
	}

	if sr.targetsCount[Target{Name: "XML", Selector: "/*"}] != 0 {
		t.Fatalf("Unexpected target XML:/* present")
	}

	m, ok := sr.GetResultsFor(300, 0, Target{Name: "REQUEST_URI_RAW"})
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "aaaaaaabc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}

	m, ok = sr.GetResultsFor(200, 0, Target{Name: "ARGS"})
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "abccc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}

	m, ok = sr.GetResultsFor(200, 1, Target{Name: "ARGS"})
	if ok {
		t.Fatalf("Unexpected match found")
	}
}

func TestGetExprsRx(t *testing.T) {
	r1 := &RuleItem{Predicate: RulePredicate{Op: Rx, Val: Value{StringToken("abc+")}}}
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
	r1 := &RuleItem{Predicate: RulePredicate{Op: BeginsWith, Val: Value{StringToken("你好")}}}
	ee := getRxExprs(r1)
	assert.NotNil(ee)
	assert.Equal("^你好", ee[0])
	re := regexp.MustCompile(ee[0])
	assert.True(re.MatchString("你好d"))
	assert.False(re.MatchString("d^你好d"))
}

func TestGetExprsBeginsWith(t *testing.T) {
	assert := assert.New(t)
	r1 := &RuleItem{Predicate: RulePredicate{Op: BeginsWith, Val: Value{StringToken("^abc")}}}
	ee := getRxExprs(r1)
	assert.NotNil(ee)
	assert.Equal("^\\^abc", ee[0])
	re := regexp.MustCompile(ee[0])
	assert.True(re.MatchString("^abcd"))
	assert.False(re.MatchString("dabcd"))
}

func TestGetExprsEndsWith(t *testing.T) {
	assert := assert.New(t)
	r1 := &RuleItem{Predicate: RulePredicate{Op: EndsWith, Val: Value{StringToken("$abc")}}}
	ee := getRxExprs(r1)
	assert.NotNil(ee)
	assert.Equal("\\$abc$", ee[0])
	re := regexp.MustCompile(ee[0])
	assert.True(re.MatchString("d$abc"))
	assert.False(re.MatchString("abcd"))
}

func TestGetExprsContains(t *testing.T) {
	assert := assert.New(t)
	r1 := &RuleItem{Predicate: RulePredicate{Op: Contains, Val: Value{StringToken("a b.c")}}}
	ee := getRxExprs(r1)
	assert.NotNil(ee)
	assert.Equal("a b\\.c", ee[0])
	re := regexp.MustCompile(ee[0])
	assert.True(re.MatchString("da b.c"))
	assert.False(re.MatchString("ab cd"))
}

func TestGetExprsStrmatch(t *testing.T) {
	assert := assert.New(t)
	r1 := &RuleItem{Predicate: RulePredicate{Op: Strmatch, Val: Value{StringToken("a b.c")}}}
	ee := getRxExprs(r1)
	assert.NotNil(ee)
	assert.Equal("a b\\.c", ee[0])
	re := regexp.MustCompile(ee[0])
	assert.True(re.MatchString("da b.c"))
	assert.False(re.MatchString("ab cd"))
}

func TestGetExprsContainsWord(t *testing.T) {
	assert := assert.New(t)
	r1 := &RuleItem{Predicate: RulePredicate{Op: ContainsWord, Val: Value{StringToken("a$bc")}}}
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
	r1 := &RuleItem{Predicate: RulePredicate{Op: Streq, Val: Value{StringToken("a$bc")}}}
	ee := getRxExprs(r1)
	assert.NotNil(ee)
	assert.Equal("^a\\$bc$", ee[0])
	re := regexp.MustCompile(ee[0])
	assert.True(re.MatchString("a$bc"))
	assert.False(re.MatchString("a$bcd"))
}

func TestGetExprsWithin(t *testing.T) {
	assert := assert.New(t)
	r1 := &RuleItem{Predicate: RulePredicate{Op: Within, Val: Value{StringToken("abc$ def ghi")}}}
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

	if ee[0] != "(?i:abc)" {
		t.Fatalf("Invalid expression %s", ee[0])
	}

	if ee[1] != "(?i:def)" {
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
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)
	err3 := rse.ScanBodyField(waf.URLEncodedContent, "arg1", "aaaaaaabccc", sr)

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

	m, ok := sr.GetResultsFor(300, 0, Target{Name: "REQUEST_URI_RAW"})
	if ok {
		t.Fatalf("Unexpected match found")
	}

	m, ok = sr.GetResultsFor(200, 0, Target{Name: "ARGS"})
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "abccc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}

	m, ok = sr.GetResultsFor(200, 1, Target{Name: "ARGS"})
	if ok {
		t.Fatalf("Unexpected match found")
	}
}

func TestReqScannerBodyFieldXML(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules, _ := newMockRuleLoader().Rules("some ruleset")
	req := &mockWafHTTPRequest{uri: "/hello.php"}

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)
	err3 := rse.ScanBodyField(waf.XMLContent, "", "aaaaaaabccc", sr)

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

	_, ok := sr.GetResultsFor(200, 0, Target{Name: "ARGS"})
	if ok {
		t.Fatalf("Unexpected match found")
	}

	_, ok = sr.GetResultsFor(400, 0, Target{Name: "XML", Selector: "/*"})
	if !ok {
		t.Fatalf("Match not found")
	}
}

func TestReqScannerBodyFieldJSON(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules, _ := newMockRuleLoader().Rules("some ruleset")
	req := &mockWafHTTPRequest{uri: "/hello.php"}

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)
	err3 := rse.ScanBodyField(waf.JSONContent, "", "aaaaaaabccc", sr)

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

	_, ok := sr.GetResultsFor(400, 0, Target{Name: "XML", Selector: "/*"})
	if ok {
		t.Fatalf("Unexpected match found")
	}

	_, ok = sr.GetResultsFor(200, 0, Target{Name: "ARGS"})
	if !ok {
		t.Fatalf("Match not found")
	}
}

func TestReqScannerSimpleSelectorUrl(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "ARGS", Selector: "myarg"}}, Op: Rx, Val: Value{StringToken("ab+c")}},
					Transformations: []Transformation{},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/hello.php?myarg=aaaaaaabccc"}

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	_, ok := sr.GetResultsFor(100, 0, Target{Name: "ARGS"})
	if ok {
		t.Fatalf("Unexpected match found")
	}

	_, ok = sr.GetResultsFor(100, 0, Target{Name: "ARGS", Selector: "myarg"})
	if !ok {
		t.Fatalf("Match not found")
	}
}

func TestReqScannerSimpleSelectorBody(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "ARGS", Selector: "myarg"}}, Op: Rx, Val: Value{StringToken("ab+c")}},
					Transformations: []Transformation{},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/hello.php"}

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)
	err3 := rse.ScanBodyField(waf.URLEncodedContent, "myarg", "aaaaaaabccc", sr)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}
	if err3 != nil {
		t.Fatalf("Got unexpected error: %s", err3)
	}

	_, ok := sr.GetResultsFor(100, 0, Target{Name: "ARGS"})
	if ok {
		t.Fatalf("Unexpected match found")
	}

	_, ok = sr.GetResultsFor(100, 0, Target{Name: "ARGS", Selector: "myarg"})
	if !ok {
		t.Fatalf("Match not found")
	}
}

func TestReqScannerSimpleSelectorHeader(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "REQUEST_HEADERS", Selector: "My-Header"}}, Op: Rx, Val: Value{StringToken("ab+c")}},
					Transformations: []Transformation{},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/hello.php"}
	req.headers = append(req.headers, &mockHeaderPair{k: "My-Header", v: "aaaaaaabccc"})

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	_, ok := sr.GetResultsFor(100, 0, Target{Name: "REQUEST_HEADERS"})
	if ok {
		t.Fatalf("Unexpected match found")
	}

	_, ok = sr.GetResultsFor(100, 0, Target{Name: "REQUEST_HEADERS", Selector: "My-Header"})
	if !ok {
		t.Fatalf("Match not found")
	}
}

func TestReqScannerFilename(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "REQUEST_FILENAME"}}, Op: Rx, Val: Value{StringToken("/p1/a%20bc.php")}}, // REQUEST_FILENAME should not URL-decode
					Transformations: []Transformation{},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/p1/a%20bc.php?arg1=something"}

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	m, ok := sr.GetResultsFor(100, 0, Target{Name: "REQUEST_FILENAME"})
	if !ok {
		t.Fatalf("Match not found")
	}

	if string(m.Data) != "/p1/a%20bc.php" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
}

func TestReqScannerFilename2(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "REQUEST_FILENAME"}}, Op: Rx, Val: Value{StringToken("/")}}, // REQUEST_FILENAME should not URL-decode
					Transformations: []Transformation{},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/"}

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	m, ok := sr.GetResultsFor(100, 0, Target{Name: "REQUEST_FILENAME"})
	if !ok {
		t.Fatalf("Match not found")
	}

	if string(m.Data) != "/" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
}

func TestReqScannerBasename(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "REQUEST_BASENAME"}}, Op: Rx, Val: Value{StringToken("a%20bc.php")}}, // REQUEST_BASE should not URL-decode
					Transformations: []Transformation{},
				},
			},
		},
	}
	reqs := []*mockWafHTTPRequest{
		{uri: "/p1/p2/a%20bc.php?arg1=something"},
		{uri: "/p1/a%20bc.php?arg1=something"},
		{uri: "/a%20bc.php?arg1=something"},
		{uri: "a%20bc.php?arg1=something"},
		{uri: "a%20bc.php"},
	}

	for _, req := range reqs {
		// Act
		rs, err1 := rsf.NewReqScanner(rules)
		s, _ := rs.NewScratchSpace()
		rse := rs.NewReqScannerEvaluation(s)
		sr, err2 := rse.ScanHeaders(req)

		// Assert
		if err1 != nil {
			t.Fatalf("Got unexpected error: %s", err1)
		}
		if err2 != nil {
			t.Fatalf("Got unexpected error: %s", err2)
		}

		m, ok := sr.GetResultsFor(100, 0, Target{Name: "REQUEST_BASENAME"})
		if !ok {
			t.Fatalf("Match not found")
		}

		if string(m.Data) != "a%20bc.php" {
			t.Fatalf("Unexpected match data: %s", string(m.Data))
		}
	}
}

func TestReqScannerBasenameEmpty(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "REQUEST_BASENAME"}}, Op: Streq, Val: Value{}},
					Transformations: []Transformation{},
				},
			},
		},
	}
	reqs := []*mockWafHTTPRequest{
		{uri: "/p1/p2/?arg1=something"},
		{uri: "/p1/?arg1=something"},
		{uri: "/?arg1=something"},
		{uri: "?arg1=something"},
		{uri: ""},
	}

	for _, req := range reqs {
		// Act
		rs, err1 := rsf.NewReqScanner(rules)
		s, _ := rs.NewScratchSpace()
		rse := rs.NewReqScannerEvaluation(s)
		sr, err2 := rse.ScanHeaders(req)

		// Assert
		if err1 != nil {
			t.Fatalf("Got unexpected error: %s", err1)
		}
		if err2 != nil {
			t.Fatalf("Got unexpected error: %s", err2)
		}

		m, ok := sr.GetResultsFor(100, 0, Target{Name: "REQUEST_BASENAME"})
		if !ok {
			t.Fatalf("Match not found")
		}

		if string(m.Data) != "" {
			t.Fatalf("Unexpected match data: %s", string(m.Data))
		}
	}
}

func TestReqScannerRequestLine(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "REQUEST_LINE"}}, Op: Rx, Val: Value{StringToken("a%20bc")}}, // REQUEST_LINE should not URL-decode
					Transformations: []Transformation{},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/a%20bc.php?arg1=something"}

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	m, ok := sr.GetResultsFor(100, 0, Target{Name: "REQUEST_LINE"})
	if !ok {
		t.Fatalf("Match not found")
	}

	if string(m.Data) != "a%20bc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
}

func TestReqCookies(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "REQUEST_COOKIES"}}, Op: Rx, Val: Value{StringToken("ab+c")}},
					Transformations: []Transformation{},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/hello.php"}
	req.headers = append(req.headers, &mockHeaderPair{k: "Cookie", v: "mycookie1=aaaaaaabccc"})

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}
	_, ok := sr.GetResultsFor(100, 0, Target{Name: "REQUEST_COOKIES"})
	if !ok {
		t.Fatalf("Match not found")
	}
}

func TestReqCookiesSelectors(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "REQUEST_COOKIES", Selector: "mycookie1"}}, Op: Rx, Val: Value{StringToken("ab+c")}},
					Transformations: []Transformation{},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/hello.php"}
	req.headers = append(req.headers, &mockHeaderPair{k: "Cookie", v: "mycookie1=aaaaaaabccc"})

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}
	_, ok := sr.GetResultsFor(100, 0, Target{Name: "REQUEST_COOKIES"})
	if ok {
		t.Fatalf("Unexpected match found")
	}
	_, ok = sr.GetResultsFor(100, 0, Target{Name: "REQUEST_COOKIES", Selector: "mycookie1"})
	if !ok {
		t.Fatalf("Match not found")
	}
}

func TestReqCookiesRegexSelector(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "REQUEST_COOKIES", Selector: "S?SESS[a-f0-9]+", IsRegexSelector: true}}, Op: Rx, Val: Value{StringToken("ab+c")}},
					Transformations: []Transformation{},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/hello.php"}
	req.headers = append(req.headers, &mockHeaderPair{k: "Cookie", v: "zzzSSESS1a2bzzz=aaaaaaabccc"})

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}
	_, ok := sr.GetResultsFor(100, 0, Target{Name: "REQUEST_COOKIES"})
	if ok {
		t.Fatalf("Unexpected match found")
	}
	_, ok = sr.GetResultsFor(100, 0, Target{Name: "REQUEST_COOKIES", Selector: "S?SESS[a-f0-9]+", IsRegexSelector: true})
	if !ok {
		t.Fatalf("Match not found")
	}
}

func TestReqCookiesRegexSelectorMultipleSameTransformations(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "REQUEST_COOKIES", Selector: "helloworld+", IsRegexSelector: true}}, Op: Rx, Val: Value{StringToken("abc+")}},
					Transformations: []Transformation{},
				},
			},
		},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "REQUEST_COOKIES", Selector: "helloworld+", IsRegexSelector: true}}, Op: Rx, Val: Value{StringToken("ab+c")}},
					Transformations: []Transformation{},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/hello.php"}
	req.headers = append(req.headers, &mockHeaderPair{k: "Cookie", v: "helloworldddddddd=aaaaaaabccc"})

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	_, ok := sr.GetResultsFor(100, 0, Target{Name: "REQUEST_COOKIES"})
	if ok {
		t.Fatalf("Unexpected match for 100 found")
	}
	_, ok = sr.GetResultsFor(100, 0, Target{Name: "REQUEST_COOKIES", Selector: "helloworld+", IsRegexSelector: true})
	if !ok {
		t.Fatalf("Match for 100 not found")
	}
	_, ok = sr.GetResultsFor(200, 0, Target{Name: "REQUEST_COOKIES", Selector: "helloworld+", IsRegexSelector: true})
	if !ok {
		t.Fatalf("Match for 200 not found")
	}
}

func TestReqCookiesRegexSelectorMultipleDifferentTranformations(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "REQUEST_COOKIES", Selector: "helloworld+", IsRegexSelector: true}}, Op: Rx, Val: Value{StringToken("abc+")}},
					Transformations: []Transformation{},
				},
			},
		},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "REQUEST_COOKIES", Selector: "helloworld+", IsRegexSelector: true}}, Op: Rx, Val: Value{StringToken("ab+c")}},
					Transformations: []Transformation{Lowercase},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/hello.php"}
	req.headers = append(req.headers, &mockHeaderPair{k: "Cookie", v: "helloworldddddddd=aaaaaaabccc"})

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	_, ok := sr.GetResultsFor(100, 0, Target{Name: "REQUEST_COOKIES"})
	if ok {
		t.Fatalf("Unexpected match for 100 found")
	}
	_, ok = sr.GetResultsFor(100, 0, Target{Name: "REQUEST_COOKIES", Selector: "helloworld+", IsRegexSelector: true})
	if !ok {
		t.Fatalf("Match for 100 not found")
	}
	_, ok = sr.GetResultsFor(200, 0, Target{Name: "REQUEST_COOKIES", Selector: "helloworld+", IsRegexSelector: true})
	if !ok {
		t.Fatalf("Match for 200 not found")
	}
}

func TestReqCookiesRegexSelectorMultipleTargets(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{
						{Name: "REQUEST_COOKIES", Selector: "helloworld1+", IsRegexSelector: true},
						{Name: "REQUEST_COOKIES", Selector: "helloworld2+", IsRegexSelector: true},
					}, Op: Rx, Val: Value{StringToken("abc+")}},
					Transformations: []Transformation{},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/hello.php"}
	req.headers = append(req.headers, &mockHeaderPair{k: "Cookie", v: "helloworld11111111=aaaaaaabccc; helloworld22222222=aaaaaaabccc"})

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	_, ok := sr.GetResultsFor(100, 0, Target{Name: "REQUEST_COOKIES"})
	if ok {
		t.Fatalf("Unexpected match for 100 found")
	}
	_, ok = sr.GetResultsFor(100, 0, Target{Name: "REQUEST_COOKIES", Selector: "helloworld1+", IsRegexSelector: true})
	if !ok {
		t.Fatalf("Match for 100 not found")
	}
	_, ok = sr.GetResultsFor(100, 0, Target{Name: "REQUEST_COOKIES", Selector: "helloworld2+", IsRegexSelector: true})
	if !ok {
		t.Fatalf("Match for 100 not found")
	}
}

func TestReqScannerMultiArgs(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules, _ := newMockRuleLoader().Rules("some ruleset")
	req := &mockWafHTTPRequest{uri: "/hello.php?arg1=aaaaaaabccc&arg2=xxyzz"}

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	m, ok := sr.GetResultsFor(200, 0, Target{Name: "ARGS"})
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "abccc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}

	m, ok = sr.GetResultsFor(200, 1, Target{Name: "ARGS"})
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "xyz" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
}

func TestReqScannerMultiArgsNoVals(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "ARGS_NAMES"}}, Op: Rx, Val: Value{StringToken("arg1")}},
					Transformations: []Transformation{},
				},
			},
		},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "ARGS_NAMES"}}, Op: Rx, Val: Value{StringToken("arg2")}},
					Transformations: []Transformation{},
				},
			},
		}}
	req := &mockWafHTTPRequest{uri: "/hello.php?arg1=&arg2="}

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	m, ok := sr.GetResultsFor(100, 0, Target{Name: "ARGS_NAMES"})
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "arg1" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}

	m, ok = sr.GetResultsFor(200, 0, Target{Name: "ARGS_NAMES"})
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "arg2" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
}

func TestReqScannerMultiArgsNoVals2(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "ARGS_NAMES"}}, Op: Rx, Val: Value{StringToken("arg1")}},
					Transformations: []Transformation{},
				},
			},
		},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "ARGS_NAMES"}}, Op: Rx, Val: Value{StringToken("arg2")}},
					Transformations: []Transformation{},
				},
			},
		}}
	req := &mockWafHTTPRequest{uri: "/hello.php?arg1&arg2"}

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	m, ok := sr.GetResultsFor(100, 0, Target{Name: "ARGS_NAMES"})
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "arg1" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}

	m, ok = sr.GetResultsFor(200, 0, Target{Name: "ARGS_NAMES"})
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "arg2" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
}

// Ensure that semicolon is NOT treated as delimiter in query strings.
func TestReqScannerMultiArgsSemicolonDelimiterNegative(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules, _ := newMockRuleLoader().Rules("some ruleset")
	req := &mockWafHTTPRequest{uri: "/hello.php?arg1=aaaaaaabccc;something=xxyzz"}

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	m, ok := sr.GetResultsFor(100, 0, Target{Name: "ARGS"})
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "aaaaaaabc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}

	m, ok = sr.GetResultsFor(200, 1, Target{Name: "ARGS"})
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "xyz" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
}

func TestReqScannerTolerateInvalidUrlEncoding(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: Rx, Val: Value{StringToken("a%xxb")}},
					Transformations: []Transformation{},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/hello.php?arg1=a%xxb"}

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}
	_, ok := sr.GetResultsFor(100, 0, Target{Name: "ARGS"})
	if !ok {
		t.Fatalf("Match not found")
	}
}

func TestDetectXssOperator(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: DetectXSS, Val: Value{}},
					Transformations: []Transformation{},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/char_test?mime=text/xml&body=%3Cx:script%20xmlns:x=%22http://www.w3.org/1999/xhtml%22%20src=%22data:,alert(1)%22%20/%3E"}
	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}
	_, ok := sr.GetResultsFor(100, 0, Target{Name: "ARGS"})
	if !ok {
		t.Fatalf("Match not found")
	}
}

func TestParseQuery(t *testing.T) {
	// Arrange
	query := "abc=def&ghi=jkl=mno&pqr&=stu&hello=world&hello=world2"
	expected := map[string][]string{
		"abc":   []string{"def"},
		"ghi":   []string{"jkl=mno"},
		"pqr":   []string{""},
		"":      []string{"stu"},
		"hello": []string{"world", "world2"},
	}

	// Act
	qq, err := parseQuery(query)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if len(qq) != len(expected) {
		t.Fatalf("Got unexpected number of values from parseQuery: %v", len(qq))
	}

	for k, vv := range expected {
		if len(qq[k]) != len(expected[k]) {
			t.Fatalf("Got unexpected number of values for key: %v. Expected: %v.", len(qq[k]), len(expected[k]))
		}

		for i := range vv {
			if qq[k][i] != expected[k][i] {
				t.Fatalf("Got unexpected value for key %v: %v. Expected: %v.", k, qq[k][i], expected[k][i])
			}
		}
	}
}

func TestValidateURLEncodingOperator(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []Target{{Name: "ARGS"}}, Op: ValidateURLEncoding, Val: Value{}},
					Transformations: []Transformation{},
				},
			},
		},
	}
	req1 := &mockWafHTTPRequest{uri: "/?a=x%21x"}
	req2 := &mockWafHTTPRequest{uri: "/?a=x%ggx"}

	// Act
	rs, errReqScan := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr1, err1 := rse.ScanHeaders(req1)
	sr2, err2 := rse.ScanHeaders(req2)

	// Assert
	if errReqScan != nil {
		t.Fatalf("Got unexpected error: %s", errReqScan)
	}
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}
	_, ok := sr1.GetResultsFor(100, 0, Target{Name: "ARGS"})
	if ok {
		t.Fatalf("Unexpected match found")
	}
	_, ok = sr2.GetResultsFor(100, 0, Target{Name: "ARGS"})
	if !ok {
		t.Fatalf("Match not found")
	}
}

func TestReqScannerCount(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS", IsCount: true}}, Op: Eq, Val: Value{IntToken(4)}},
				},
			},
		},
	}

	req := &mockWafHTTPRequest{uri: "/hello.php?hello=a&hello=b&world=c"}

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)
	err3 := rse.ScanBodyField(waf.URLEncodedContent, "bodyarg1", "d", sr)

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

	n := sr.targetsCount[Target{Name: "ARGS", IsCount: true}]
	if n != 4 {
		t.Fatalf("Unexpected targets count: %v", n)
	}
}

func TestReqScannerCountWithSelector(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate: RulePredicate{Targets: []Target{{Name: "ARGS", Selector: "hello", IsCount: true}}, Op: Eq, Val: Value{IntToken(2)}},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/hello.php?hello=a&hello=b"}

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	s, _ := rs.NewScratchSpace()
	rse := rs.NewReqScannerEvaluation(s)
	sr, err2 := rse.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	n := sr.targetsCount[Target{Name: "ARGS", Selector: "hello", IsCount: true}]
	if n != 2 {
		t.Fatalf("Unexpected targets count: %v", n)
	}
}

type mockWafHTTPRequest struct {
	uri        string
	bodyReader io.Reader
	headers    []waf.HeaderPair
}

func (r *mockWafHTTPRequest) Method() string                      { return "GET" }
func (r *mockWafHTTPRequest) URI() string                         { return r.uri }
func (r *mockWafHTTPRequest) Protocol() string                    { return "HTTP/1.1" }
func (r *mockWafHTTPRequest) RemoteAddr() string                  { return "0.0.0.0" }
func (r *mockWafHTTPRequest) ConfigID() string                    { return "SecRuleConfig1" }
func (r *mockWafHTTPRequest) Headers() []waf.HeaderPair           { return r.headers }
func (r *mockWafHTTPRequest) BodyReader() io.Reader               { return r.bodyReader }
func (r *mockWafHTTPRequest) LogMetaData() waf.RequestLogMetaData { return &mockLogMetaData{} }
func (r *mockWafHTTPRequest) TransactionID() string               { return "abc" }

type mockHeaderPair struct {
	k string
	v string
}

func (h *mockHeaderPair) Key() string   { return h.k }
func (h *mockHeaderPair) Value() string { return h.v }

type mockLogMetaData struct {
}

func (h *mockLogMetaData) Scope() string     { return "Global" }
func (h *mockLogMetaData) ScopeName() string { return "Default Policy" }
