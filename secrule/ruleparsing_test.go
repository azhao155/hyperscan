package secrule

import (
	"fmt"
	"strings"
	"testing"
)

// Unit tests that only know the RuleParser interface. More "black box" than ruleparsing_impl_test.go.

func TestTwoRules(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rules := `
		SecRule ARGS "1=1" "deny,msg:'SQL Injection Attack',id:'950901'"
		SecRule ARGS "<script>" "deny,msg:'XSS Attack',id:'950902'"
	`

	// Act
	rr, err := p.Parse(rules, nil, nil)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if len(rr) != 2 {
		t.Fatalf("Wrong rule rules count: %d", len(rr))
	}

	r, ok := rr[0].(*Rule)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	if r.ID != 950901 {
		t.Fatalf("Wrong ID of 950901")
	}

	r, ok = rr[1].(*Rule)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[1])
	}

	if r.ID != 950902 {
		t.Fatalf("Wrong ID of 950902")
	}
}

func TestSecRuleSecActionMixed(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rules := `
		SecRule ARGS "1=1" "deny,msg:'SQL Injection Attack',id:'950901'"
		SecAction "id:'950903',setvar:tx.hello=0"
		SecRule ARGS "<script>" "deny,msg:'XSS Attack',id:'950902'"
	`

	// Act
	rr, err := p.Parse(rules, nil, nil)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if len(rr) != 3 {
		t.Fatalf("Wrong rule statements count: %d", len(rr))
	}

	r, ok := rr[0].(*Rule)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	if r.ID != 950901 {
		t.Fatalf("Wrong ID of 950901")
	}

	a, ok := rr[1].(*ActionStmt)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[1])
	}

	if a.ID != 950903 {
		t.Fatalf("Wrong ID of 950903")
	}

	r, ok = rr[2].(*Rule)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[1])
	}

	if r.ID != 950902 {
		t.Fatalf("Wrong ID of 950902")
	}
}

func TestInvalidStatement(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rules := `
		SecRule ARGS "1=1" "deny,msg:'SQL Injection Attack',id:'950901'"

		# Some comment
		SecRule ARGS "<script>" \
			"deny,msg:'XSS Attack',id:'950902'"

		# Another comment
		Something something something
	`

	// Act
	rr, err := p.Parse(rules, nil, nil)

	// Assert
	if err == nil {
		t.Fatalf("Expected error, but err was nil")
	}

	if err.Error() != "unknown statement on line 9: Something something something" {
		t.Fatalf("Error message was not as expected. Got: %s", err)
	}

	if len(rr) != 2 {
		t.Fatalf("Wrong rule rules count: %d", len(rr))
	}
}

func TestCommentedRuleWithDanglingArg(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rules := `
		#SecAction \
			"id:'900004', \
			phase:1, \
			t:none, \
			setvar:tx.anomaly_score_blocking=on, \
			nolog, \
			pass"
	`

	// Act
	rr, err := p.Parse(rules, nil, nil)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	n := len(rr)
	if n != 0 {
		t.Fatalf("Wrong rule rules count: %d", n)
	}
}

func TestMissingId(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rules := `
		SecRule ARGS "1=1" "deny,msg:'SQL Injection Attack'"
	`

	// Act
	rr, err := p.Parse(rules, nil, nil)

	// Assert
	if len(rr) != 0 {
		t.Fatalf("Wrong rule rules count: %d", len(rr))
	}

	if err == nil {
		t.Fatalf("Expected error, but err was nil")
	}

	expected := "parse error in SecRule on line 2: missing ID"
	if err.Error() != expected {
		t.Fatalf("Error message was not as expected. Got: %s. Expected: %s", err, expected)
	}
}

func TestSecRuleTrailingArg(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rules := `
		SecRule ARGS "1=1" "id:123,deny,msg:'SQL Injection Attack'" something
	`

	// Act
	rr, err := p.Parse(rules, nil, nil)

	// Assert
	if len(rr) != 0 {
		t.Fatalf("Wrong rule rules count: %d", len(rr))
	}

	if err == nil {
		t.Fatalf("Expected error, but err was nil")
	}

	expected := "parse error in SecRule on line 2: unexpected arg: something"
	if err.Error() != expected {
		t.Fatalf("Error message was not as expected. Got: %s. Expected: %s", err, expected)
	}
}

func TestMissingChain(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rules := `
		SecRule ARGS "1=1" "deny,msg:'SQL Injection Attack',id:'950901',chain"
		SecRule ARGS "2=2" "deny,msg:'SQL Injection Attack'"
		SecRule ARGS "3=3" "deny,msg:'SQL Injection Attack'"
	`

	// Act
	rr, err := p.Parse(rules, nil, nil)

	// Assert
	if len(rr) != 1 {
		t.Fatalf("Wrong rule rules count: %d", len(rr))
	}

	if err == nil {
		t.Fatalf("Expected error, but err was nil")
	}

	expected := "parse error in SecRule on line 4: missing ID"
	if err.Error() != expected {
		t.Fatalf("Error message was not as expected. Got: %s. Expected: %s", err, expected)
	}
}

func TestChaining(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rules := `
		SecRule ARGS "<script>" "deny,msg:'XSS Attack',id:'950902'"
		SecRule ARGS "1=1" "deny,msg:'SQL Injection Attack',id:'950901',chain"
		SecRule ARGS "2=2" "deny,msg:'SQL Injection Attack',chain"
		SecRule ARGS "3=3" "deny,msg:'SQL Injection Attack'"
		SecRule ARGS "<vbscript>" "deny,msg:'XSS Attack',id:'950904'"
	`

	// Act
	rr, err := p.Parse(rules, nil, nil)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	n := len(rr)
	if n != 3 {
		t.Fatalf("Wrong rule rules count: %d", n)
	}

	r, ok := rr[0].(*Rule)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	n = len(r.Items)
	if n != 1 {
		t.Fatalf("Wrong rule items count in rule 0: %d", n)
	}

	r, ok = rr[1].(*Rule)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[1])
	}

	n = len(r.Items)
	if len(r.Items) != 3 {
		t.Fatalf("Wrong rule items count in rule 1: %d", n)
	}

	r, ok = rr[2].(*Rule)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[2])
	}

	n = len(r.Items)
	if n != 1 {
		t.Fatalf("Wrong rule items count in rule 2: %d", n)
	}
}

func TestNoActions(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rules := `
		SecRule ARGS "1=1" "deny,msg:'SQL Injection Attack',id:'950901',chain"
		SecRule ARGS "2=2"
	`

	// Act
	rr, err := p.Parse(rules, nil, nil)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	n := len(rr)
	if n != 1 {
		t.Fatalf("Wrong rules count: %d", n)
	}

	r, ok := rr[0].(*Rule)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	n = len(r.Items)
	if n != 2 {
		t.Fatalf("Wrong rule items count in rule 0: %d", n)
	}
}

func TestSecRuleTargets(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	type testcase struct {
		input    string
		expected []Target
	}
	tests := []testcase{
		{`ARGS|ARGS_NAMES`, []Target{{Name: TargetArgs}, {Name: TargetArgsNames}}},
		{`ARGS,ARGS_NAMES`, []Target{{Name: TargetArgs}, {Name: TargetArgsNames}}},
		{`ARGS:/helloworld/`, []Target{{Name: TargetArgs, Selector: "helloworld", IsRegexSelector: true}}},
		{`ARGS|ARGS:/helloworld/|ARGS_NAMES`, []Target{{Name: TargetArgs}, {Name: TargetArgs, Selector: "helloworld", IsRegexSelector: true}, {Name: TargetArgsNames}}},
		{`ARGS,ARGS:/helloworld/,ARGS_NAMES`, []Target{{Name: TargetArgs}, {Name: TargetArgs, Selector: "helloworld", IsRegexSelector: true}, {Name: TargetArgsNames}}},
		{`ARGS|REQUEST_COOKIES:/S?SESS[a-f0-9]+/|ARGS_NAMES`, []Target{{Name: TargetArgs}, {Name: TargetRequestCookies, Selector: "S?SESS[a-f0-9]+", IsRegexSelector: true}, {Name: TargetArgsNames}}},
		{`REQUEST_HEADERS:X.Filename`, []Target{{Name: TargetRequestHeaders, Selector: "X.Filename"}}},
		{`"ARGS|ARGS_NAMES"`, []Target{{Name: TargetArgs}, {Name: TargetArgsNames}}},
		{`"ARGS,ARGS_NAMES"`, []Target{{Name: TargetArgs}, {Name: TargetArgsNames}}},
		{`"ARGS:'helloworld'"`, []Target{{Name: TargetArgs, Selector: "helloworld"}}},
		{`"ARGS:'hello world'"`, []Target{{Name: TargetArgs, Selector: "hello world"}}},
		{`"ARGS:'hello \"world'"`, []Target{{Name: TargetArgs, Selector: `hello "world`}}},
		{`"ARGS:'hello \\'world'"`, []Target{{Name: TargetArgs, Selector: `hello 'world`}}},
		{`"ARGS:'/helloworld/'"`, []Target{{Name: TargetArgs, Selector: `helloworld`, IsRegexSelector: true}}},
		{`"ARGS|ARGS:'helloworld'|ARGS_NAMES"`, []Target{{Name: TargetArgs}, {Name: TargetArgs, Selector: "helloworld"}, {Name: TargetArgsNames}}},
		{`"ARGS,ARGS:'helloworld',ARGS_NAMES"`, []Target{{Name: TargetArgs}, {Name: TargetArgs, Selector: "helloworld"}, {Name: TargetArgsNames}}},
		{`"REQUEST_HEADERS:X.Filename"`, []Target{{Name: TargetRequestHeaders, Selector: "X.Filename"}}},
		{`'ARGS|ARGS_NAMES'`, []Target{{Name: TargetArgs}, {Name: TargetArgsNames}}},
		{`'ARGS:\'helloworld\''`, []Target{{Name: TargetArgs, Selector: "helloworld"}}},
		{`'ARGS:\'hello world\''`, []Target{{Name: TargetArgs, Selector: "hello world"}}},
		{`'ARGS:\'hello "world\''`, []Target{{Name: TargetArgs, Selector: `hello "world`}}},
		{`'ARGS:\'hello \\\'world\''`, []Target{{Name: TargetArgs, Selector: `hello 'world`}}},
		{`'ARGS|ARGS:\'helloworld\'|ARGS_NAMES'`, []Target{{Name: TargetArgs}, {Name: TargetArgs, Selector: "helloworld"}, {Name: TargetArgsNames}}},
		{`XML:/abc|ARGS`, []Target{{Name: TargetXML, Selector: "/abc"}, {Name: TargetArgs}}},
		{`XML:/abc,ARGS`, []Target{{Name: TargetXML, Selector: "/abc"}, {Name: TargetArgs}}},
		{`XML:/*|ARGS`, []Target{{Name: TargetXML, Selector: "/*"}, {Name: TargetArgs}}},
		{`XML:/*,ARGS`, []Target{{Name: TargetXML, Selector: "/*"}, {Name: TargetArgs}}},
		{`XML://`, []Target{{Name: TargetXML, Selector: "//"}}},
		{`XML:/abc/`, []Target{{Name: TargetXML, Selector: "/abc/"}}},
		{`'REQUEST_HEADERS:X.Filename'`, []Target{{Name: TargetRequestHeaders, Selector: "X.Filename"}}},
		{`ARGS:list[select]|ARGS_NAMES`, []Target{{Name: TargetArgs, Selector: "list[select]"}, {Name: TargetArgsNames}}},
		{`ARGS:'list[select]'|ARGS_NAMES`, []Target{{Name: TargetArgs, Selector: "list[select]"}, {Name: TargetArgsNames}}},
		{`ARGS:/abc[0-9]/|ARGS_NAMES`, []Target{{Name: TargetArgs, Selector: "abc[0-9]", IsRegexSelector: true}, {Name: TargetArgsNames}}},
		{`"ARGS| ARGS_NAMES"`, []Target{{Name: TargetArgs}, {Name: TargetArgsNames}}},
		{"\"ARGS| \\\nARGS_NAMES\"", []Target{{Name: TargetArgs}, {Name: TargetArgsNames}}},
		{`ARGS:/ab|cd/|ARGS_NAMES`, []Target{{Name: TargetArgs, Selector: "ab|cd", IsRegexSelector: true}, {Name: TargetArgsNames}}},
		{`ARGS:'/ab|cd/'|ARGS_NAMES`, []Target{{Name: TargetArgs, Selector: "ab|cd", IsRegexSelector: true}, {Name: TargetArgsNames}}},
		{`ARGS:/ab/|ARGS:/cd/`, []Target{{Name: TargetArgs, Selector: "ab", IsRegexSelector: true}, {Name: TargetArgs, Selector: "cd", IsRegexSelector: true}}},
	}

	// Act and assert
	var b strings.Builder
	for _, test := range tests {
		rr, err := p.Parse("SecRule "+test.input+` "<script>" "id:'950902'"`, nil, nil)

		if err != nil {
			fmt.Fprintf(&b, "Got unexpected error: %s. Tested input: %s\n", err, test.input)
			continue
		}

		n := len(rr)
		if n != 1 {
			fmt.Fprintf(&b, "Wrong rules count: %d. Tested input: %s\n", n, test.input)
			continue
		}

		r, ok := rr[0].(*Rule)
		if !ok {
			t.Fatalf("Wrong statement type: %T", rr[0])
		}

		n = len(r.Items)
		if n != 1 {
			fmt.Fprintf(&b, "Wrong rule items count in rule 0: %d. Tested input: %s\n", n, test.input)
			continue
		}

		n = len(r.Items[0].Predicate.Targets)
		if n != len(test.expected) {
			fmt.Fprintf(&b, "Wrong targets count: %d. Tested input: %s\n", n, test.input)
			continue
		}

		for i, val := range test.expected {
			if r.Items[0].Predicate.Targets[i] != val {
				fmt.Fprintf(&b, "Wrong target: %v. Expected: %v. Tested input: %v\n", r.Items[0].Predicate.Targets[i], val, test.input)
			}
		}
	}

	if b.Len() > 0 {
		t.Fatalf("\n%s", b.String())
	}
}

func TestSecRuleTargetExclusions(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	type testcase struct {
		input                 string
		expectedTargets       []Target
		expectedExceptTargets []Target
	}
	tests := []testcase{
		{`ARGS|!ARGS:aaa`, []Target{{Name: TargetArgs}}, []Target{{Name: TargetArgs, Selector: "aaa"}}},
		{`!ARGS:aaa|ARGS`, []Target{{Name: TargetArgs}}, []Target{{Name: TargetArgs, Selector: "aaa"}}},
		{`ARGS|!ARGS:aaa|ARGS_NAMES`, []Target{{Name: TargetArgs}, {Name: TargetArgsNames}}, []Target{{Name: TargetArgs, Selector: "aaa"}}},
		{`ARGS|!ARGS:/aaa./`, []Target{{Name: TargetArgs}}, []Target{{Name: TargetArgs, Selector: "aaa.", IsRegexSelector: true}}},
		{`ARGS|!ARGS:/aaa./|ARGS_NAMES`, []Target{{Name: TargetArgs}, {Name: TargetArgsNames}}, []Target{{Name: TargetArgs, Selector: "aaa.", IsRegexSelector: true}}},
	}

	// Act and assert
	var b strings.Builder
	for _, test := range tests {
		rr, err := p.Parse("SecRule "+test.input+` "<script>" "id:'950902'"`, nil, nil)

		if err != nil {
			fmt.Fprintf(&b, "Got unexpected error: %s. Tested input: %s\n", err, test.input)
			continue
		}

		n := len(rr)
		if n != 1 {
			fmt.Fprintf(&b, "Wrong rules count: %d. Tested input: %s\n", n, test.input)
			continue
		}

		r, ok := rr[0].(*Rule)
		if !ok {
			t.Fatalf("Wrong statement type: %T", rr[0])
		}

		n = len(r.Items)
		if n != 1 {
			fmt.Fprintf(&b, "Wrong rule items count in rule 0: %d. Tested input: %s\n", n, test.input)
			continue
		}

		n = len(r.Items[0].Predicate.Targets)
		if n != len(test.expectedTargets) {
			fmt.Fprintf(&b, "Wrong targets count: %d. Tested input: %s\n", n, test.input)
			continue
		}

		for i, val := range test.expectedTargets {
			if r.Items[0].Predicate.Targets[i] != val {
				fmt.Fprintf(&b, "Wrong target: %v. Tested input: %v\n", r.Items[0].Predicate.Targets[i], test.input)
			}
		}

		n = len(r.Items[0].Predicate.ExceptTargets)
		if n != len(test.expectedExceptTargets) {
			fmt.Fprintf(&b, "Wrong target exclusions count: %d. Tested input: %v\n", n, test.input)
			continue
		}

		for i, val := range test.expectedExceptTargets {
			if r.Items[0].Predicate.ExceptTargets[i] != val {
				fmt.Fprintf(&b, "Wrong target exclusion: %v. Tested input: %v\n", r.Items[0].Predicate.ExceptTargets[i], test.input)
			}
		}
	}

	if b.Len() > 0 {
		t.Fatalf("\n%s", b.String())
	}
}

func TestSecRuleTargetErrors(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	type testcase struct {
		input       string
		expectedErr string
	}
	tests := []testcase{
		{`|`, `parse error in SecRule on line 1: unable to parse targets`},
	}

	// Act and assert
	var b strings.Builder
	for _, test := range tests {
		_, err := p.Parse("SecRule "+test.input+` "<script>" "id:'950902'"`, nil, nil)

		if err == nil {
			t.Fatalf("Expected error, but err was nil")
		} else if err.Error() != test.expectedErr {
			fmt.Fprintf(&b, "Error message was not as expected. Expected: %s. Got: %s", test.expectedErr, err)
		}
	}

	if b.Len() > 0 {
		t.Fatalf("%s", b.String())
	}
}

func TestSecRuleOperators(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	type testcase struct {
		input string
		op    Operator
		val   Value
		neg   bool
	}
	tests := []testcase{
		{`helloworld`, Rx, Value{StringToken(`helloworld`)}, false},
		{`"hello world"`, Rx, Value{StringToken(`hello world`)}, false},
		{`"hello \"world"`, Rx, Value{StringToken(`hello "world`)}, false},
		{`"hello 'world"`, Rx, Value{StringToken(`hello 'world`)}, false},
		{`'hello world'`, Rx, Value{StringToken(`hello world`)}, false},
		{`'hello "world'`, Rx, Value{StringToken(`hello "world`)}, false},
		{`"@rx hello world"`, Rx, Value{StringToken(`hello world`)}, false},
		{`"@contains helloworld"`, Contains, Value{StringToken(`helloworld`)}, false},
		{`'@contains helloworld'`, Contains, Value{StringToken(`helloworld`)}, false},
		{`'@ipMatchFromFile https://example.com/file.txt'`, IPMatchFromFile, Value{StringToken(`https://example.com/file.txt`)}, false},
		{`'@detectSQLi'`, DetectSQLi, Value{}, false},
		{`'@DeTeCtSqLi'`, DetectSQLi, Value{}, false},
		{`!helloworld`, Rx, Value{StringToken(`helloworld`)}, true},
		{`"!helloworld"`, Rx, Value{StringToken(`helloworld`)}, true},
		{`"!@rx helloworld"`, Rx, Value{StringToken(`helloworld`)}, true},
	}

	// Act and assert
	var b strings.Builder
	for _, test := range tests {
		rr, err := p.Parse("SecRule ARGS "+test.input+` "id:'950902'"`, nil, nil)

		if err != nil {
			fmt.Fprintf(&b, "Got unexpected error: %s. Tested input: %s\n", err, test.input)
			continue
		}

		n := len(rr)
		if n != 1 {
			fmt.Fprintf(&b, "Wrong rules count: %d. Tested input: %s\n", n, test.input)
			continue
		}

		r, ok := rr[0].(*Rule)
		if !ok {
			t.Fatalf("Wrong statement type: %T", rr[0])
		}

		n = len(r.Items)
		if n != 1 {
			fmt.Fprintf(&b, "Wrong rule items count in rule 0: %d. Tested input: %s\n", n, test.input)
			continue
		}

		if r.Items[0].Predicate.Op != test.op {
			fmt.Fprintf(&b, "Wrong Operator: %d. Tested input: %s\n", r.Items[0].Predicate.Op, test.input)
			continue
		}

		if !r.Items[0].Predicate.Val.equal(test.val) {
			fmt.Fprintf(&b, "Wrong value: %s. Tested input: %s\n", r.Items[0].Predicate.Val, test.input)
			continue
		}

		if r.Items[0].Predicate.Neg != test.neg {
			fmt.Fprintf(&b, "Wrong negate value: %t. Tested input: %s\n", r.Items[0].Predicate.Neg, test.input)
			continue
		}
	}

	if b.Len() > 0 {
		t.Fatalf("\n%s", b.String())
	}
}

func TestSecRuleActions(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	type testcase struct {
		input           string
		expectedID      int
		expectedActions []Action
	}
	tests := []testcase{
		{`ID:950902`, 950902, []Action{}},
		{`id:950902`, 950902, []Action{}},
		{`id:'950902'`, 950902, []Action{}},
		{`id:'950902',allow`, 950902, []Action{&AllowAction{}}},
		{`id:'950902',deny`, 950902, []Action{&DenyAction{}}},
		{`"id:'950902'"`, 950902, []Action{}},
		{`"id:'950902',deny"`, 950902, []Action{&DenyAction{}}},
		{`"   id:'950902',deny"`, 950902, []Action{&DenyAction{}}},
		{`'id:\'950902\''`, 950902, []Action{}},
		{`'id:\'950902\',deny'`, 950902, []Action{&DenyAction{}}},
		{`"id:'950902',deny,msg:'Hello World Attack'"`, 950902, []Action{&DenyAction{}, &MsgAction{Msg: Value{StringToken("Hello World Attack")}}}},
		{`"id:950902,setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}"`, 950902, []Action{
			&SetVarAction{
				variable: Value{StringToken("tx.sql_injection_score")},
				operator: increment,
				value:    Value{MacroToken("tx.critical_anomaly_score")},
			},
		}},
		{`"id:'950902',setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}'"`, 950902, []Action{
			&SetVarAction{
				variable: Value{StringToken("tx.sql_injection_score")},
				operator: increment,
				value:    Value{MacroToken("tx.critical_anomaly_score")},
			},
		}},
		{`"id:'950902',logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}'"`, 950902, []Action{
			&LogDataAction{LogData: Value{
				StringToken("Matched Data: "),
				MacroToken("tx.0"),
				StringToken(" found within "),
				MacroToken("matched_var_name"),
				StringToken(": "),
				MacroToken("matched_var")}},
		}},
	}

	// Act and assert
	var b strings.Builder
	for _, test := range tests {
		rr, err := p.Parse("SecRule ARGS helloworld "+test.input, nil, nil)

		if err != nil {
			fmt.Fprintf(&b, "Got unexpected error: %s. Tested input: %s\n", err, test.input)
			continue
		}

		n := len(rr)
		if n != 1 {
			fmt.Fprintf(&b, "Wrong rules count: %d. Tested input: %s\n", n, test.input)
			continue
		}

		r, ok := rr[0].(*Rule)
		if !ok {
			t.Fatalf("Wrong statement type: %T", rr[0])
		}

		n = len(r.Items)
		if n != 1 {
			fmt.Fprintf(&b, "Wrong rule items count in rule 0: %d. Tested input: %s\n", n, test.input)
			continue
		}

		if r.ID != test.expectedID {
			fmt.Fprintf(&b, "Wrong id: %v. Tested input: %s\n", r.ID, test.input)
			continue
		}

		compareActions(test.expectedActions, r.Items[0].Actions, &b, test.input)
	}

	if b.Len() > 0 {
		t.Fatalf("\n%s", b.String())
	}
}

func compareActions(expectedActions []Action, actualActions []Action, b *strings.Builder, rawinput string) {
	if len(expectedActions) != len(actualActions) {
		fmt.Fprintf(b, "Wrong actions count. Expected: %v. Actual: %v. Tested input: %s\n", len(expectedActions), len(actualActions), rawinput)
		return
	}

	for i, expectedVal := range expectedActions {
		a := actualActions[i]

		switch a := a.(type) {
		case *RawAction:
			expectedVal, ok := expectedVal.(*RawAction)
			if !ok {
				fmt.Fprintf(b, "Wrong expected action type. Tested input: %s\n", rawinput)
				continue
			}

			if a.Key != expectedVal.Key {
				fmt.Fprintf(b, "Got wrong action key: %s. Expected: %s. Tested input: %s\n", a.Key, expectedVal.Key, rawinput)
			}

			if a.Val != expectedVal.Val {
				fmt.Fprintf(b, "Got wrong action val: %s. Expected: %s. Tested input: %s\n", a.Val, expectedVal.Val, rawinput)
			}

		case *DenyAction:
			_, ok := expectedVal.(*DenyAction)
			if !ok {
				fmt.Fprintf(b, "Wrong expected action type. Tested input: %s\n", rawinput)
				continue
			}

		case *NoLogAction:
			_, ok := expectedVal.(*NoLogAction)
			if !ok {
				fmt.Fprintf(b, "Wrong expected action type. Tested input: %s\n", rawinput)
				continue
			}

		case *MsgAction:
			expectedVal, ok := expectedVal.(*MsgAction)
			if !ok {
				fmt.Fprintf(b, "Wrong expected action type. Tested input: %s\n", rawinput)
				continue
			}

			if !a.Msg.equal(expectedVal.Msg) {
				fmt.Fprintf(b, "Unexpected Msg: %v", a.Msg)
				continue
			}

		case *LogDataAction:
			expectedVal, ok := expectedVal.(*LogDataAction)
			if !ok {
				fmt.Fprintf(b, "Wrong expected action type. Tested input: %s\n", rawinput)
				continue
			}

			if !a.LogData.equal(expectedVal.LogData) {
				fmt.Fprintf(b, "Unexpected LogData: %v. Expected: %v.", a.LogData, expectedVal.LogData)
				continue
			}

		case *SetVarAction:
			expectedVal, ok := expectedVal.(*SetVarAction)
			if !ok {
				fmt.Fprintf(b, "Wrong expected action type. Tested input: %s\n", rawinput)
				continue
			}

			if !a.variable.equal(expectedVal.variable) {
				fmt.Fprintf(b, "Wrong variable: %v. Tested input: %v\n", a.variable, rawinput)
				continue
			}

			if a.operator != expectedVal.operator {
				fmt.Fprintf(b, "Wrong operator: %v. Tested input: %v\n", a.operator, rawinput)
				continue
			}

			if !a.value.equal(expectedVal.value) {
				fmt.Fprintf(b, "Wrong value: %v. Tested input: %v\n", a.value, rawinput)
				continue
			}

		case *LogAction:
			_, ok := expectedVal.(*LogAction)
			if !ok {
				fmt.Fprintf(b, "Wrong expected action type. Tested input: %s\n", rawinput)
				continue
			}

		case *AllowAction:
			_, ok := expectedVal.(*AllowAction)
			if !ok {
				fmt.Fprintf(b, "Wrong expected action type. Tested input: %s\n", rawinput)
				continue
			}

		case *CaptureAction:
			_, ok := expectedVal.(*CaptureAction)
			if !ok {
				fmt.Fprintf(b, "Wrong expected action type. Tested input: %s\n", rawinput)
				continue
			}

		case *CtlAction:
			expectedVal, ok := expectedVal.(*CtlAction)
			if !ok {
				fmt.Fprintf(b, "Got wrong action type: %T. Expected: %T. Tested input: %s\n", a, expectedVal, rawinput)
				continue
			}

			if a.setting != expectedVal.setting {
				fmt.Fprintf(b, "Wrong variable: %v. Tested input: %v\n", a.setting, rawinput)
				continue
			}

			if !a.value.equal(expectedVal.value) {
				fmt.Fprintf(b, "Wrong value: %v. Tested input: %v\n", a.value, rawinput)
				continue
			}

		default:
			fmt.Fprintf(b, "Test harness does not support this type yet: %T. Please implement.", a)

		}
	}
}

func TestTransformationCaseInsensitive(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rule := `
		SecRule ARGS "helloworld" "t:cssDecode,t:UrLdEcOdEuNi,id:942320"
	`

	// Act
	rr, err := p.Parse(rule, nil, nil)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	rc, ok := rr[0].(*Rule)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	if len(rc.Items) != 1 {
		t.Fatalf("Unexpected rule count: %d", len(rc.Items))
	}

	r := rc.Items[0]

	expectedTransformations := []Transformation{CSSDecode, URLDecodeUni}
	if len(r.Transformations) != len(expectedTransformations) {
		t.Fatalf("Unexpected transformations count. Actual: %d. Expected: %d.", len(r.Transformations), len(expectedTransformations))
	}
	for i := range expectedTransformations {
		if r.Transformations[i] != expectedTransformations[i] {
			t.Fatalf("Unexpected transformation. Actual: %d. Expected: %d.", r.Transformations[i], expectedTransformations[i])
		}
	}
}

func TestSecAction900990(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rule := `
		SecAction \
		  "id:900990,\
		  msg:'this message isnt actually in the original 900990',\
		  phase:1,\
		  nolog,\
		  pass,\
		  t:none,\
		  setvar:tx.crs_setup_version=300"
	`

	// Act
	rr, err := p.Parse(rule, nil, nil)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	a, ok := rr[0].(*ActionStmt)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	if a.ID != 900990 {
		t.Fatalf("Unexpected ID: %d", a.ID)
	}

	expectedPhase := 1
	if a.Phase != expectedPhase {
		t.Fatalf("Unexpected phase. Actual: %v. Expected: %v.", a.Phase, expectedPhase)
	}

	expectedActions := []Action{
		&MsgAction{Msg: Value{StringToken("this message isnt actually in the original 900990")}},
		&NoLogAction{},
		&RawAction{`pass`, ``},
		&SetVarAction{
			variable: Value{StringToken("tx.crs_setup_version")},
			operator: set,
			value:    Value{IntToken(300)},
		},
	}
	var b strings.Builder
	compareActions(expectedActions, a.Actions, &b, "")
	if b.Len() > 0 {
		t.Fatalf("\n%s", b.String())
	}

}

func TestRule942320(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rule := `
		SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "(?i:(?:procedure\s+analyse\s*?\()|(?:;\s*?(declare|open)\s+[\w-]+)|(?:create\s+(procedure|function)\s*?\w+\s*?\(\s*?\)\s*?-)|(?:declare[^\w]+[@#]\s*?\w+)|(exec\s*?\(\s*?@))" \
		"phase:request,\
		rev:'2',\
		ver:'OWASP_CRS/3.0.0',\
		maturity:'9',\
		accuracy:'8',\
		capture,\
		t:none,t:urlDecodeUni,\
		block,\
		msg:'Detects MySQL and PostgreSQL stored procedure/function injections',\
		id:942320,\
		tag:'application-multi',\
		tag:'language-multi',\
		tag:'platform-multi',\
		tag:'attack-sqli',\
		tag:'OWASP_CRS/WEB_ATTACK/SQL_INJECTION',\
		tag:'WASCTC/WASC-19',\
		tag:'OWASP_TOP_10/A1',\
		tag:'OWASP_AppSensor/CIE1',\
		tag:'PCI/6.5.2',\
		logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
		severity:'CRITICAL',\
		setvar:'tx.msg=%{rule.msg}',\
		setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score},\
		setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},\
		setvar:'tx.%{rule.id}-OWASP_CRS/WEB_ATTACK/SQLI-%{matched_var_name}=%{tx.0}'"
	`

	// Act
	rr, err := p.Parse(rule, nil, nil)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	rc, ok := rr[0].(*Rule)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	if rc.ID != 942320 {
		t.Fatalf("Unexpected rule ID: %d", rc.ID)
	}

	if len(rc.Items) != 1 {
		t.Fatalf("Unexpected rule count: %d", len(rc.Items))
	}

	r := rc.Items[0]

	expectedTargets := []Target{{Name: TargetRequestCookies}, {Name: TargetRequestCookiesNames}, {Name: TargetArgsNames}, {Name: TargetArgs}, {Name: TargetXML, Selector: "/*"}}
	if len(r.Predicate.Targets) != len(expectedTargets) {
		t.Fatalf("Unexpected targets count. Actual: %d. Expected: %d.", len(r.Predicate.Targets), len(expectedTargets))
	}
	for i := range expectedTargets {
		if r.Predicate.Targets[i] != expectedTargets[i] {
			t.Fatalf("Unexpected target. Actual: %v. Expected: %v.", r.Predicate.Targets[i], expectedTargets[i])
		}
	}

	expectedExceptTargets := []Target{{Name: TargetRequestCookies, Selector: "__utm", IsRegexSelector: true}}
	if len(r.Predicate.ExceptTargets) != len(expectedExceptTargets) {
		t.Fatalf("Unexpected except-targets count. Actual: %d. Expected: %d.", len(r.Predicate.ExceptTargets), len(expectedExceptTargets))
	}
	for i := range expectedExceptTargets {
		if r.Predicate.ExceptTargets[i] != expectedExceptTargets[i] {
			t.Fatalf("Unexpected except-targets. Actual: %v. Expected: %v.", r.Predicate.ExceptTargets[i], expectedExceptTargets[i])
		}
	}

	if r.Predicate.Op != Rx {
		t.Fatalf("Unexpected Operator: %d", r.Predicate.Op)
	}

	if r.Predicate.Neg != false {
		t.Fatalf("Unexpected neg value: %t", r.Predicate.Neg)
	}

	expectedVal := Value{StringToken(`(?i:(?:procedure\s+analyse\s*?\()|(?:;\s*?(declare|open)\s+[\w-]+)|(?:create\s+(procedure|function)\s*?\w+\s*?\(\s*?\)\s*?-)|(?:declare[^\w]+[@#]\s*?\w+)|(exec\s*?\(\s*?@))`)}
	if !r.Predicate.Val.equal(expectedVal) {
		t.Fatalf("Unexpected Operator value. Actual: %s. Expected: %s", r.Predicate.Val, expectedVal)
	}

	expectedPhase := 2
	if rc.Phase != expectedPhase {
		t.Fatalf("Unexpected phase. Actual: %v. Expected: %v.", rc.Phase, expectedPhase)
	}

	expectedActions := []Action{
		&RawAction{`rev`, `2`},
		&RawAction{`ver`, `OWASP_CRS/3.0.0`},
		&RawAction{`maturity`, `9`},
		&RawAction{`accuracy`, `8`},
		&CaptureAction{},
		&RawAction{`block`, ``},
		&MsgAction{Msg: Value{StringToken("Detects MySQL and PostgreSQL stored procedure/function injections")}},
		&RawAction{`tag`, `application-multi`},
		&RawAction{`tag`, `language-multi`},
		&RawAction{`tag`, `platform-multi`},
		&RawAction{`tag`, `attack-sqli`},
		&RawAction{`tag`, `OWASP_CRS/WEB_ATTACK/SQL_INJECTION`},
		&RawAction{`tag`, `WASCTC/WASC-19`},
		&RawAction{`tag`, `OWASP_TOP_10/A1`},
		&RawAction{`tag`, `OWASP_AppSensor/CIE1`},
		&RawAction{`tag`, `PCI/6.5.2`},
		&LogDataAction{LogData: Value{
			StringToken("Matched Data: "),
			MacroToken("tx.0"),
			StringToken(" found within "),
			MacroToken("matched_var_name"),
			StringToken(": "),
			MacroToken("matched_var")}},
		&RawAction{`severity`, `CRITICAL`},
		&SetVarAction{
			variable: Value{StringToken("tx.msg")},
			operator: set,
			value:    Value{MacroToken("rule.msg")},
		},
		&SetVarAction{
			variable: Value{StringToken("tx.sql_injection_score")},
			operator: increment,
			value:    Value{MacroToken("tx.critical_anomaly_score")},
		},
		&SetVarAction{
			variable: Value{StringToken("tx.anomaly_score")},
			operator: increment,
			value:    Value{MacroToken("tx.critical_anomaly_score")},
		},

		&SetVarAction{
			variable: Value{StringToken("tx."), MacroToken("rule.id"), StringToken("-OWASP_CRS/WEB_ATTACK/SQLI-"), MacroToken("matched_var_name")},
			operator: set,
			value:    Value{MacroToken("tx.0")},
		},
	}

	var b strings.Builder
	compareActions(expectedActions, r.Actions, &b, "")
	if b.Len() > 0 {
		t.Fatalf("\n%s", b.String())
	}

	expectedTransformations := []Transformation{None, URLDecodeUni}
	if len(r.Transformations) != len(expectedTransformations) {
		t.Fatalf("Unexpected transformations count. Actual: %d. Expected: %d.", len(r.Transformations), len(expectedTransformations))
	}
	for i := range expectedTransformations {
		if r.Transformations[i] != expectedTransformations[i] {
			t.Fatalf("Unexpected transformation. Actual: %d. Expected: %d.", r.Transformations[i], expectedTransformations[i])
		}
	}
}

func TestRule901001(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rule := `
        SecRule &TX:crs_setup_version "@eq 0" \
        "id:901001,\
        phase:1,\
        auditlog,\
        log,\
        deny,\
        status:500,\
        severity:CRITICAL,\
        msg:''"
    `

	// Act
	rr, err := p.Parse(rule, nil, nil)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	rc, ok := rr[0].(*Rule)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	if rc.ID != 901001 {
		t.Fatalf("Unexpected rule ID: %d", rc.ID)
	}

	if len(rc.Items) != 1 {
		t.Fatalf("Unexpected rule count: %d", len(rc.Items))
	}

	r := rc.Items[0]

	expectedTargets := []Target{{Name: TargetTx, Selector: "crs_setup_version", IsCount: true}}
	if len(r.Predicate.Targets) != len(expectedTargets) {
		t.Fatalf("Unexpected targets count. Actual: %d. Expected: %d.", len(r.Predicate.Targets), len(expectedTargets))
	}
	for i := range expectedTargets {
		if r.Predicate.Targets[i] != expectedTargets[i] {
			t.Fatalf("Unexpected target. Actual: %v. Expected: %v.", r.Predicate.Targets[i], expectedTargets[i])
		}
	}

	if r.Predicate.Op != Eq {
		t.Fatalf("Unexpected Operator: %d", r.Predicate.Op)
	}

	if r.Predicate.Neg != false {
		t.Fatalf("Unexpected neg value: %t", r.Predicate.Neg)
	}

	expectedVal := Value{IntToken(0)}
	if !r.Predicate.Val.equal(expectedVal) {
		t.Fatalf("Unexpected Operator value. Actual: %s. Expected: %s", r.Predicate.Val, expectedVal)
	}

	expectedPhase := 1
	if rc.Phase != expectedPhase {
		t.Fatalf("Unexpected phase. Actual: %v. Expected: %v.", rc.Phase, expectedPhase)
	}

	expectedActions := []Action{
		&RawAction{`auditlog`, ``},
		&LogAction{},
		&DenyAction{},
		&RawAction{`status`, `500`},
		&RawAction{`severity`, `CRITICAL`},
		&MsgAction{Msg: Value{StringToken("")}},
	}
	var b strings.Builder
	compareActions(expectedActions, r.Actions, &b, "")
	if b.Len() > 0 {
		t.Fatalf("\n%s", b.String())
	}

	expectedTransformations := []Transformation{URLDecodeUni}
	if len(r.Transformations) != 0 {
		t.Fatalf("Unexpected transformations count. Actual: %d. Expected: %d.", len(r.Transformations), len(expectedTransformations))
	}
}

func TestPhraseFunc(t *testing.T) {
	// Arrange
	callbackArg := ""
	p := NewRuleParser()
	cb := func(f string) ([]string, error) {
		callbackArg = f
		return []string{}, nil
	}

	// Act
	_, err := p.Parse(`SecRule ARGS "@pmf test.data" "deny,msg:'SQL Injection Attack',id:'950901'"`, cb, nil)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if callbackArg != "test.data" {
		t.Fatalf("callback got unexpected arg: %v", callbackArg)
	}
}

func TestInclude(t *testing.T) {
	// Arrange
	callbackArg := ""
	p := NewRuleParser()
	cb := func(filePath string) (statements []Statement, err error) {
		callbackArg = filePath
		return []Statement{}, nil
	}

	// Act
	_, err := p.Parse(`iNcLuDe hello.conf`, nil, cb)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if callbackArg != "hello.conf" {
		t.Fatalf("callback got unexpected arg: %v", callbackArg)
	}
}

func TestNolog(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rule := `SecRule ARGS "hello" "id:901001,nolog"`

	// Act
	rr, err := p.Parse(rule, nil, nil)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	rc, ok := rr[0].(*Rule)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	expectedActions := []Action{
		&NoLogAction{},
	}
	var b strings.Builder
	compareActions(expectedActions, rc.Items[0].Actions, &b, "")
	if b.Len() > 0 {
		t.Fatalf("\n%s", b.String())
	}
}

func TestCaptureAction(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rule := `SecRule ARGS "hello" "id:901001,capture"`

	// Act
	rr, err := p.Parse(rule, nil, nil)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	rc, ok := rr[0].(*Rule)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	expectedActions := []Action{
		&CaptureAction{},
	}
	var b strings.Builder
	compareActions(expectedActions, rc.Items[0].Actions, &b, "")
	if b.Len() > 0 {
		t.Fatalf("\n%s", b.String())
	}
}

func TestPhase(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rule := `
		SecRule ARGS "hello" "id:901001,phase:4"
		SecAction "id:901002,phase:4"
	`

	// Act
	rr, err := p.Parse(rule, nil, nil)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	rc, ok := rr[0].(*Rule)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	if rc.Phase != 4 {
		t.Fatalf("Unexpected phase: %v", rc.Phase)
	}

	a, ok := rr[1].(*ActionStmt)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	if a.Phase != 4 {
		t.Fatalf("Unexpected phase: %v", a.Phase)
	}
}

func TestPhaseChain1(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rule := `
		SecRule ARGS "hello" "id:901001,chain,phase:3"
		SecRule ARGS "abc" ""
	`

	// Act
	rr, err := p.Parse(rule, nil, nil)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	rc, ok := rr[0].(*Rule)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	if rc.Phase != 3 {
		t.Fatalf("Unexpected phase: %v", rc.Phase)
	}
}

func TestPhaseChain2(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rule := `
		SecRule ARGS "hello" "id:901001,chain"
		SecRule ARGS "abc" "phase:3"
	`

	// Act
	rr, err := p.Parse(rule, nil, nil)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	rc, ok := rr[0].(*Rule)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	if rc.Phase != 3 {
		t.Fatalf("Unexpected phase: %v", rc.Phase)
	}
}

func TestPhaseChainConflicting(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rule := `
		SecRule ARGS "hello" "id:901001,chain,phase:3"
		SecRule ARGS "abc" "phase:4"
	`

	// Act
	_, err := p.Parse(rule, nil, nil)

	// Assert
	if err.Error() != "parse error in SecRule on line 3: rule chain has conflicting phases" {
		t.Fatalf("Error message was not as expected. Got: %s", err)
	}
}

func TestMarker(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rule := `
		SecMarker hello1
		SecMarker "hello2"
		SecMarker 'hello3'
	`

	// Act
	rr, err := p.Parse(rule, nil, nil)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if len(rr) != 3 {
		t.Fatalf("Wrong rule rules count: %d", len(rr))
	}

	m, ok := rr[0].(*Marker)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	if m.Label != "hello1" {
		t.Fatalf("Unexpected label: %v", m.Label)
	}

	m, ok = rr[1].(*Marker)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	if m.Label != "hello2" {
		t.Fatalf("Unexpected label: %v", m.Label)
	}

	m, ok = rr[2].(*Marker)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	if m.Label != "hello3" {
		t.Fatalf("Unexpected label: %v", m.Label)
	}
}

func TestParseSkipAfter(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rule := `
		SecRule ARGS "hello" "id:12345,skipAfter:somelabel"
	`

	// Act
	rr, err := p.Parse(rule, nil, nil)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	rc, ok := rr[0].(*Rule)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	if len(rc.Items) != 1 {
		t.Fatalf("Unexpected rule count: %d", len(rc.Items))
	}

	r := rc.Items[0]

	found := false
	for _, a := range r.Actions {
		if a, ok := a.(*SkipAfterAction); ok {
			found = true
			if a.Label != "somelabel" {
				t.Fatalf("Unexpected label: %v", a.Label)
			}
		}
	}

	if !found {
		t.Fatalf("Did not find skipAfter action")
	}
}

func TestParseSetVar(t *testing.T) {
	// Arrange
	type testCase struct {
		input    string
		expected SetVarAction
	}
	tests := []testCase{
		{
			`tx.anomaly_score=123`,
			SetVarAction{
				variable: Value{StringToken("tx.anomaly_score")},
				operator: set,
				value:    Value{IntToken(123)},
			},
		},
		{
			`tx.anomaly_score=+123`,
			SetVarAction{
				variable: Value{StringToken("tx.anomaly_score")},
				operator: increment,
				value:    Value{IntToken(123)},
			},
		},
		{
			`tx.anomaly_score=-123`,
			SetVarAction{
				variable: Value{StringToken("tx.anomaly_score")},
				operator: decrement,
				value:    Value{IntToken(123)},
			},
		},
		{
			`!tx.anomaly_score`,
			SetVarAction{
				variable: Value{StringToken("tx.anomaly_score")},
				operator: deleteVar,
				value:    Value{IntToken(1)},
			},
		},
		{
			`tx.anomaly_score=+%{tx.critical_anomaly_score}`,
			SetVarAction{
				variable: Value{StringToken("tx.anomaly_score")},
				operator: increment,
				value:    Value{MacroToken("tx.critical_anomaly_score")},
			},
		},
		{
			`tx.anomaly_score=%{tx.critical_anomaly_score} %{tx.something}`,
			SetVarAction{
				variable: Value{StringToken("tx.anomaly_score")},
				operator: set,
				value:    Value{MacroToken("tx.critical_anomaly_score"), StringToken(" "), MacroToken("tx.something")},
			},
		},
		{
			`%{tx.something}=+%{tx.critical_anomaly_score}`,
			SetVarAction{
				variable: Value{MacroToken("tx.something")},
				operator: increment,
				value:    Value{MacroToken("tx.critical_anomaly_score")},
			},
		},
	}

	var b strings.Builder
	for _, test := range tests {
		// Act
		sv, err := parseSetVarAction(test.input)

		// Assert
		if err != nil {
			fmt.Fprintf(&b, "Got unexpected error: %s. Tested input: %s\n", err, test.input)
			continue
		}

		compareActions([]Action{&test.expected}, []Action{&sv}, &b, test.input)
	}

	if b.Len() > 0 {
		t.Fatalf("\n%s", b.String())
	}
}

func TestCtlAction(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rule := `
		SecRule REQBODY_PROCESSOR "!@rx (?:URLENCODED|MULTIPART|XML|JSON)" \
		"id:901340,\
		ctl:forceRequestBodyVariable=On"\
	`

	// Act
	rr, err := p.Parse(rule, nil, nil)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	rc, ok := rr[0].(*Rule)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	if len(rc.Items) != 1 {
		t.Fatalf("Unexpected rule count: %d", len(rc.Items))
	}

	r := rc.Items[0]
	expectedActions := []Action{
		&CtlAction{
			setting: ForceRequestBodyVariable,
			value:   Value{StringToken("On")},
		},
	}

	var b strings.Builder
	compareActions(expectedActions, r.Actions, &b, "")
	if b.Len() > 0 {
		t.Fatalf("\n%s", b.String())
	}
}

func TestParseValue(t *testing.T) {
	// Arrange
	type testCase struct {
		input    string
		expected Value
	}
	tests := []testCase{
		{`hello`, Value{StringToken("hello")}},
		{`%{tx.somevar1}`, Value{MacroToken("tx.somevar1")}},
		{`hello%{tx.somevar1}`, Value{StringToken("hello"), MacroToken("tx.somevar1")}},
		{`hello%{tx.somevar1}world`, Value{StringToken("hello"), MacroToken("tx.somevar1"), StringToken("world")}},
		{`%{tx.somevar1}world`, Value{MacroToken("tx.somevar1"), StringToken("world")}},
		{`%{tx.somevar1}world%{tx.somevar2}`, Value{MacroToken("tx.somevar1"), StringToken("world"), MacroToken("tx.somevar2")}},
		{`123`, Value{IntToken(123)}},
	}

	var b strings.Builder
	for _, test := range tests {

		// Arrange
		p := NewRuleParser()
		rule := `SecRule ARGS "hello" "id:901001,msg:'` + test.input + `'"`

		// Act
		rr, err := p.Parse(rule, nil, nil)

		// Assert
		if err != nil {
			fmt.Fprintf(&b, "Got unexpected error: %s", err)
			continue
		}

		r, ok := rr[0].(*Rule)
		if !ok {
			fmt.Fprintf(&b, "Wrong statement type: %T", rr[0])
			continue
		}

		msgAction, ok := r.Items[0].Actions[0].(*MsgAction)
		if !ok {
			fmt.Fprintf(&b, "Wrong action type: %T", msgAction)
			continue
		}

		if !test.expected.equal(msgAction.Msg) {
			t.Fatalf("Unexpected msgAction.Msg: %v", msgAction.Msg)
			continue
		}
	}

	if b.Len() > 0 {
		t.Fatalf("\n%s", b.String())
	}
}

func TestTargetNamesStructsInSync(t *testing.T) {
	if len(TargetNamesFromStr) != len(TargetNamesStrings)-1 {
		t.Fatalf("len(TargetNamesFromStr) != len(targetNamesToStr)-1")
	}

	if int(_lastTarget) != len(TargetNamesStrings) {
		t.Fatalf("int(_lastTarget) != len(TargetNamesStrings)")
	}

	for i, v := range TargetNamesStrings {
		if i != int(TargetNamesFromStr[v]) {
			t.Fatalf("TargetNamesStrings in wrong order")
		}
	}
	for k, v := range TargetNamesFromStr {
		if k != TargetNamesStrings[v] {
			t.Fatalf("TargetNamesFromStr does not match TargetNamesStrings")
		}
	}
}
