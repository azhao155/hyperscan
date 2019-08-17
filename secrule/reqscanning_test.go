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

	if !sr.targetsPresent["REQUEST_URI_RAW"] {
		t.Fatalf("Target REQUEST_URI_RAW not present")
	}

	if sr.targetsPresent["XML:/*"] {
		t.Fatalf("Unexpected target XML:/* present")
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

func TestReqScannerSimpleSelectorUrl(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules := []Statement{
		&Rule{
			ID: 100,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []string{"ARGS:myarg"}, Op: Rx, Val: "ab+c"},
					Transformations: []Transformation{},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/hello.php?myarg=aaaaaaabccc"}

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

	_, ok := sr.GetRxResultsFor(100, 0, "ARGS")
	if ok {
		t.Fatalf("Unexpected match found")
	}

	_, ok = sr.GetRxResultsFor(100, 0, "ARGS:myarg")
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
					Predicate:       RulePredicate{Targets: []string{"ARGS:myarg"}, Op: Rx, Val: "ab+c"},
					Transformations: []Transformation{},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/hello.php"}

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	sr, err2 := rs.ScanHeaders(req)
	err3 := rs.ScanBodyField(waf.URLEncodedContent, "myarg", "aaaaaaabccc", sr)

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

	_, ok := sr.GetRxResultsFor(100, 0, "ARGS")
	if ok {
		t.Fatalf("Unexpected match found")
	}

	_, ok = sr.GetRxResultsFor(100, 0, "ARGS:myarg")
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
					Predicate:       RulePredicate{Targets: []string{"REQUEST_HEADERS:My-Header"}, Op: Rx, Val: "ab+c"},
					Transformations: []Transformation{},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/hello.php"}
	req.headers = append(req.headers, &mockHeaderPair{k: "My-Header", v: "aaaaaaabccc"})

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

	_, ok := sr.GetRxResultsFor(100, 0, "REQUEST_HEADERS")
	if ok {
		t.Fatalf("Unexpected match found")
	}

	_, ok = sr.GetRxResultsFor(100, 0, "REQUEST_HEADERS:My-Header")
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
					Predicate:       RulePredicate{Targets: []string{"REQUEST_FILENAME"}, Op: Rx, Val: "/p1/a%20bc.php"}, // REQUEST_FILENAME should not URL-decode
					Transformations: []Transformation{},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/p1/a%20bc.php?arg1=something"}

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

	m, ok := sr.GetRxResultsFor(100, 0, "REQUEST_FILENAME")
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
					Predicate:       RulePredicate{Targets: []string{"REQUEST_FILENAME"}, Op: Rx, Val: "/"}, // REQUEST_FILENAME should not URL-decode
					Transformations: []Transformation{},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/"}

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

	m, ok := sr.GetRxResultsFor(100, 0, "REQUEST_FILENAME")
	if !ok {
		t.Fatalf("Match not found")
	}

	if string(m.Data) != "/" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
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
					Predicate:       RulePredicate{Targets: []string{"REQUEST_LINE"}, Op: Rx, Val: "a%20bc"}, // REQUEST_LINE should not URL-decode
					Transformations: []Transformation{},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/a%20bc.php?arg1=something"}

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

	m, ok := sr.GetRxResultsFor(100, 0, "REQUEST_LINE")
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
					Predicate:       RulePredicate{Targets: []string{"REQUEST_COOKIES"}, Op: Rx, Val: "ab+c"},
					Transformations: []Transformation{},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/hello.php"}
	req.headers = append(req.headers, &mockHeaderPair{k: "Cookie", v: "mycookie1=aaaaaaabccc"})
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
	_, ok := sr.GetRxResultsFor(100, 0, "REQUEST_COOKIES")
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
					Predicate:       RulePredicate{Targets: []string{"REQUEST_COOKIES:mycookie1"}, Op: Rx, Val: "ab+c"},
					Transformations: []Transformation{},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/hello.php"}
	req.headers = append(req.headers, &mockHeaderPair{k: "Cookie", v: "mycookie1=aaaaaaabccc"})
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
	_, ok := sr.GetRxResultsFor(100, 0, "REQUEST_COOKIES")
	if ok {
		t.Fatalf("Unexpected match found")
	}
	_, ok = sr.GetRxResultsFor(100, 0, "REQUEST_COOKIES:mycookie1")
	if !ok {
		t.Fatalf("Match not found")
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
	sr, err2 := rs.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	m, ok := sr.GetRxResultsFor(200, 0, "ARGS")
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "abccc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}

	m, ok = sr.GetRxResultsFor(200, 1, "ARGS")
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
					Predicate:       RulePredicate{Targets: []string{"ARGS_NAMES"}, Op: Rx, Val: "arg1"},
					Transformations: []Transformation{},
				},
			},
		},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []string{"ARGS_NAMES"}, Op: Rx, Val: "arg2"},
					Transformations: []Transformation{},
				},
			},
		}}
	req := &mockWafHTTPRequest{uri: "/hello.php?arg1=&arg2="}

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

	m, ok := sr.GetRxResultsFor(100, 0, "ARGS_NAMES")
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "arg1" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}

	m, ok = sr.GetRxResultsFor(200, 0, "ARGS_NAMES")
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
					Predicate:       RulePredicate{Targets: []string{"ARGS_NAMES"}, Op: Rx, Val: "arg1"},
					Transformations: []Transformation{},
				},
			},
		},
		&Rule{
			ID: 200,
			Items: []RuleItem{
				{
					Predicate:       RulePredicate{Targets: []string{"ARGS_NAMES"}, Op: Rx, Val: "arg2"},
					Transformations: []Transformation{},
				},
			},
		}}
	req := &mockWafHTTPRequest{uri: "/hello.php?arg1&arg2"}

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

	m, ok := sr.GetRxResultsFor(100, 0, "ARGS_NAMES")
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "arg1" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}

	m, ok = sr.GetRxResultsFor(200, 0, "ARGS_NAMES")
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
	sr, err2 := rs.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	m, ok := sr.GetRxResultsFor(100, 0, "ARGS")
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "aaaaaaabc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
	if m.StartPos != 0 {
		t.Fatalf("Unexpected match pos: %d", m.StartPos)
	}
	if m.EndPos != 9 {
		t.Fatalf("Unexpected match pos: %d", m.EndPos)
	}

	m, ok = sr.GetRxResultsFor(200, 1, "ARGS")
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "xyz" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}

	// Note: the positions here are expected to be relative to what comes after arg1=, because the semicolon is not an acceptable delimiter here
	if m.StartPos != 23 {
		t.Fatalf("Unexpected match pos: %d", m.StartPos)
	}
	if m.EndPos != 26 {
		t.Fatalf("Unexpected match pos: %d", m.EndPos)
	}
}

func TestReqScannerInvalidUrlEncoding(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules, _ := newMockRuleLoader().Rules("some ruleset")
	req := &mockWafHTTPRequest{uri: "/hello.php?arg1=a%xxb"}

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	_, err2 := rs.ScanHeaders(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 == nil {
		t.Fatalf("Expected an error, but got nil")
	}
	if err2.Error() != "invalid URL escape \"%xx\"" {
		t.Fatalf("Got unexpected error: %s", err2)
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
					Predicate:       RulePredicate{Targets: []string{"ARGS"}, Op: DetectXSS, Val: ""},
					Transformations: []Transformation{},
				},
			},
		},
	}
	req := &mockWafHTTPRequest{uri: "/char_test?mime=text/xml&body=%3Cx:script%20xmlns:x=%22http://www.w3.org/1999/xhtml%22%20src=%22data:,alert(1)%22%20/%3E"}
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
	_, ok := sr.GetRxResultsFor(100, 0, "ARGS")
	if !ok {
		t.Fatalf("Match not found")
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
