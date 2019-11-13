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
		{`ARGS|ARGS_NAMES`, []Target{{Name: "ARGS"}, {Name: "ARGS_NAMES"}}},
		{`ARGS,ARGS_NAMES`, []Target{{Name: "ARGS"}, {Name: "ARGS_NAMES"}}},
		{`ARGS:/helloworld/`, []Target{{Name: "ARGS", Selector: "helloworld", IsRegexSelector: true}}},
		{`ARGS|ARGS:/helloworld/|ARGS_NAMES`, []Target{{Name: "ARGS"}, {Name: "ARGS", Selector: "helloworld", IsRegexSelector: true}, {Name: "ARGS_NAMES"}}},
		{`ARGS,ARGS:/helloworld/,ARGS_NAMES`, []Target{{Name: "ARGS"}, {Name: "ARGS", Selector: "helloworld", IsRegexSelector: true}, {Name: "ARGS_NAMES"}}},
		{`ARGS|REQUEST_COOKIES:/S?SESS[a-f0-9]+/|ARGS_NAMES`, []Target{{Name: "ARGS"}, {Name: "REQUEST_COOKIES", Selector: "S?SESS[a-f0-9]+", IsRegexSelector: true}, {Name: "ARGS_NAMES"}}},
		{`REQUEST_HEADERS:X.Filename`, []Target{{Name: "REQUEST_HEADERS", Selector: "X.Filename"}}},
		{`"ARGS|ARGS_NAMES"`, []Target{{Name: "ARGS"}, {Name: "ARGS_NAMES"}}},
		{`"ARGS,ARGS_NAMES"`, []Target{{Name: "ARGS"}, {Name: "ARGS_NAMES"}}},
		{`"ARGS:'helloworld'"`, []Target{{Name: "ARGS", Selector: "helloworld"}}},
		{`"ARGS:'hello world'"`, []Target{{Name: "ARGS", Selector: "hello world"}}},
		{`"ARGS:'hello \"world'"`, []Target{{Name: "ARGS", Selector: `hello "world`}}},
		{`"ARGS:'hello \\'world'"`, []Target{{Name: "ARGS", Selector: `hello 'world`}}},
		{`"ARGS:'/helloworld/'"`, []Target{{Name: "ARGS", Selector: `helloworld`, IsRegexSelector: true}}},
		{`"ARGS|ARGS:'helloworld'|ARGS_NAMES"`, []Target{{Name: "ARGS"}, {Name: "ARGS", Selector: "helloworld"}, {Name: "ARGS_NAMES"}}},
		{`"ARGS,ARGS:'helloworld',ARGS_NAMES"`, []Target{{Name: "ARGS"}, {Name: "ARGS", Selector: "helloworld"}, {Name: "ARGS_NAMES"}}},
		{`"REQUEST_HEADERS:X.Filename"`, []Target{{Name: "REQUEST_HEADERS", Selector: "X.Filename"}}},
		{`'ARGS|ARGS_NAMES'`, []Target{{Name: "ARGS"}, {Name: "ARGS_NAMES"}}},
		{`'ARGS:\'helloworld\''`, []Target{{Name: "ARGS", Selector: "helloworld"}}},
		{`'ARGS:\'hello world\''`, []Target{{Name: "ARGS", Selector: "hello world"}}},
		{`'ARGS:\'hello "world\''`, []Target{{Name: "ARGS", Selector: `hello "world`}}},
		{`'ARGS:\'hello \\\'world\''`, []Target{{Name: "ARGS", Selector: `hello 'world`}}},
		{`'ARGS|ARGS:\'helloworld\'|ARGS_NAMES'`, []Target{{Name: "ARGS"}, {Name: "ARGS", Selector: "helloworld"}, {Name: "ARGS_NAMES"}}},
		{`XML:/abc|ARGS`, []Target{{Name: "XML", Selector: "/abc"}, {Name: "ARGS"}}},
		{`XML:/abc,ARGS`, []Target{{Name: "XML", Selector: "/abc"}, {Name: "ARGS"}}},
		{`XML:/*|ARGS`, []Target{{Name: "XML", Selector: "/*"}, {Name: "ARGS"}}},
		{`XML:/*,ARGS`, []Target{{Name: "XML", Selector: "/*"}, {Name: "ARGS"}}},
		{`XML://`, []Target{{Name: "XML", Selector: "//"}}},
		{`XML:/abc/`, []Target{{Name: "XML", Selector: "/abc/"}}},
		{`'REQUEST_HEADERS:X.Filename'`, []Target{{Name: "REQUEST_HEADERS", Selector: "X.Filename"}}},
		{`ARGS:list[select]|ARGS_NAMES`, []Target{{Name: "ARGS", Selector: "list[select]"}, {Name: "ARGS_NAMES"}}},
		{`ARGS:'list[select]'|ARGS_NAMES`, []Target{{Name: "ARGS", Selector: "list[select]"}, {Name: "ARGS_NAMES"}}},
		{`ARGS:/abc[0-9]/|ARGS_NAMES`, []Target{{Name: "ARGS", Selector: "abc[0-9]", IsRegexSelector: true}, {Name: "ARGS_NAMES"}}},
		{`"ARGS| ARGS_NAMES"`, []Target{{Name: "ARGS"}, {Name: "ARGS_NAMES"}}},
		{"\"ARGS| \\\nARGS_NAMES\"", []Target{{Name: "ARGS"}, {Name: "ARGS_NAMES"}}},
		{`ARGS:/ab|cd/|ARGS_NAMES`, []Target{{Name: "ARGS", Selector: "ab|cd", IsRegexSelector: true}, {Name: "ARGS_NAMES"}}},
		{`ARGS:'/ab|cd/'|ARGS_NAMES`, []Target{{Name: "ARGS", Selector: "ab|cd", IsRegexSelector: true}, {Name: "ARGS_NAMES"}}},
		{`ARGS:/ab/|ARGS:/cd/`, []Target{{Name: "ARGS", Selector: "ab", IsRegexSelector: true}, {Name: "ARGS", Selector: "cd", IsRegexSelector: true}}},
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
		{`ARGS|!ARGS:aaa`, []Target{{Name: `ARGS`}}, []Target{{Name: "ARGS", Selector: "aaa"}}},
		{`!ARGS:aaa|ARGS`, []Target{{Name: `ARGS`}}, []Target{{Name: "ARGS", Selector: "aaa"}}},
		{`ARGS|!ARGS:aaa|ARGS_NAMES`, []Target{{Name: "ARGS"}, {Name: "ARGS_NAMES"}}, []Target{{Name: "ARGS", Selector: "aaa"}}},
		{`ARGS|!ARGS:/aaa./`, []Target{{Name: "ARGS"}}, []Target{{Name: "ARGS", Selector: "aaa.", IsRegexSelector: true}}},
		{`ARGS|!ARGS:/aaa./|ARGS_NAMES`, []Target{{Name: "ARGS"}, {Name: "ARGS_NAMES"}}, []Target{{Name: "ARGS", Selector: "aaa.", IsRegexSelector: true}}},
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
		val   string
		neg   bool
	}
	tests := []testcase{
		{`helloworld`, Rx, `helloworld`, false},
		{`"hello world"`, Rx, `hello world`, false},
		{`"hello \"world"`, Rx, `hello "world`, false},
		{`"hello 'world"`, Rx, `hello 'world`, false},
		{`'hello world'`, Rx, `hello world`, false},
		{`'hello "world'`, Rx, `hello "world`, false},
		{`"@rx hello world"`, Rx, `hello world`, false},
		{`"@contains helloworld"`, Contains, `helloworld`, false},
		{`'@contains helloworld'`, Contains, `helloworld`, false},
		{`'@ipMatchFromFile https://example.com/file.txt'`, IPMatchFromFile, `https://example.com/file.txt`, false},
		{`'@detectSQLi'`, DetectSQLi, ``, false},
		{`'@DeTeCtSqLi'`, DetectSQLi, ``, false},
		{`!helloworld`, Rx, `helloworld`, true},
		{`"!helloworld"`, Rx, `helloworld`, true},
		{`"!@rx helloworld"`, Rx, `helloworld`, true},
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

		if r.Items[0].Predicate.Val != test.val {
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
		{`"id:'950902',deny,msg:'Hello World Attack'"`, 950902, []Action{&DenyAction{}, &MsgAction{Msg: "Hello World Attack"}}},
		{`"id:950902,setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}"`, 950902, []Action{
			&SetVarAction{
				variable:        "tx.sql_injection_score",
				operator:        increment,
				value:           "%{tx.critical_anomaly_score}",
				varMacroMatches: nil,
				valMacroMatches: [][]string{{"%{tx.critical_anomaly_score}", "tx.critical_anomaly_score"}},
			},
		}},
		{`"id:'950902',setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}'"`, 950902, []Action{
			&SetVarAction{
				variable:        "tx.sql_injection_score",
				operator:        increment,
				value:           "%{tx.critical_anomaly_score}",
				varMacroMatches: nil,
				valMacroMatches: [][]string{{"%{tx.critical_anomaly_score}", "tx.critical_anomaly_score"}},
			},
		}},
		{`"id:'950902',logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}'"`, 950902, []Action{
			&RawAction{`logdata`, `Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}`},
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
				fmt.Fprintf(b, "Got wrong action type: %T. Expected: %T. Tested input: %s\n", a, expectedVal, rawinput)
				continue
			}

			if a.Key != expectedVal.Key {
				fmt.Fprintf(b, "Got wrong action key: %s. Expected: %s. Tested input: %s\n", a.Key, expectedVal.Key, rawinput)
			}

			if a.Val != expectedVal.Val {
				fmt.Fprintf(b, "Got wrong action val: %s. Expected: %s. Tested input: %s\n", a.Val, expectedVal.Val, rawinput)
			}

		case *DenyAction:
			expectedVal, ok := expectedVal.(*DenyAction)
			if !ok {
				fmt.Fprintf(b, "Got wrong action type: %T. Expected: %T. Tested input: %s\n", a, expectedVal, rawinput)
				continue
			}

		case *NoLogAction:
			expectedVal, ok := expectedVal.(*NoLogAction)
			if !ok {
				fmt.Fprintf(b, "Got wrong action type: %T. Expected: %T. Tested input: %s\n", a, expectedVal, rawinput)
				continue
			}

		case *MsgAction:
			expectedVal, ok := expectedVal.(*MsgAction)
			if !ok {
				fmt.Fprintf(b, "Got wrong action type: %T. Expected: %T. Tested input: %s\n", a, expectedVal, rawinput)
				continue
			}

			if a.Msg != expectedVal.Msg {
				fmt.Fprintf(b, "Got wrong action msg: %s. Expected: %s. Tested input: %s\n", a.Msg, expectedVal.Msg, rawinput)
			}

		case *SetVarAction:
			expectedVal, ok := expectedVal.(*SetVarAction)
			if !ok {
				fmt.Fprintf(b, "Got wrong action type: %T. Expected: %T. Tested input: %s\n", a, expectedVal, rawinput)
				continue
			}

			if a.variable != expectedVal.variable {
				fmt.Fprintf(b, "Wrong variable: %v. Tested input: %v\n", a.variable, rawinput)
				continue
			}

			if a.operator != expectedVal.operator {
				fmt.Fprintf(b, "Wrong operator: %v. Tested input: %v\n", a.operator, rawinput)
				continue
			}

			if a.value != expectedVal.value {
				fmt.Fprintf(b, "Wrong value: %v. Tested input: %v\n", a.value, rawinput)
				continue
			}

			if len(a.varMacroMatches) != len(expectedVal.varMacroMatches) {
				fmt.Fprintf(b, "Wrong len(varMacroMatches): %v. Tested input: %v\n", len(a.varMacroMatches), rawinput)
				continue
			}

			for i := range a.varMacroMatches {
				if len(a.varMacroMatches[i]) != len(expectedVal.varMacroMatches[i]) {
					fmt.Fprintf(b, "Wrong len(a.varMacroMatches[i]): %v. Tested input: %v\n", len(a.varMacroMatches[i]), rawinput)
					continue
				}

				for j := range a.varMacroMatches[i] {
					if a.varMacroMatches[i][j] != expectedVal.varMacroMatches[i][j] {
						fmt.Fprintf(b, "Wrong a.varMacroMatches[i][j]: %v. Tested input: %v\n", a.varMacroMatches[i][j], rawinput)
						continue
					}
				}
			}

			if len(a.valMacroMatches) != len(expectedVal.valMacroMatches) {
				fmt.Fprintf(b, "Wrong len(valMacroMatches): %v. Tested input: %v\n", len(a.valMacroMatches), rawinput)
				continue
			}

			for i := range a.valMacroMatches {
				if len(a.valMacroMatches[i]) != len(expectedVal.valMacroMatches[i]) {
					fmt.Fprintf(b, "Wrong len(a.valMacroMatches[i]): %v. Tested input: %v\n", len(a.valMacroMatches[i]), rawinput)
					continue
				}

				for j := range a.valMacroMatches[i] {
					if a.valMacroMatches[i][j] != expectedVal.valMacroMatches[i][j] {
						fmt.Fprintf(b, "Wrong a.valMacroMatches[i][j]: %v. Tested input: %v\n", a.valMacroMatches[i][j], rawinput)
						continue
					}
				}
			}

		case *LogAction:
			expectedVal, ok := expectedVal.(*LogAction)
			if !ok {
				fmt.Fprintf(b, "Got wrong action type: %T. Expected: %T. Tested input: %s\n", a, expectedVal, rawinput)
				continue
			}

		case *AllowAction:
			expectedVal, ok := expectedVal.(*AllowAction)
			if !ok {
				fmt.Fprintf(b, "Got wrong action type: %T. Expected: %T. Tested input: %s\n", a, expectedVal, rawinput)
				continue
			}

		case *CaptureAction:
			expectedVal, ok := expectedVal.(*CaptureAction)
			if !ok {
				fmt.Fprintf(b, "Got wrong action type: %T. Expected: %T. Tested input: %s\n", a, expectedVal, rawinput)
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
		&MsgAction{Msg: "this message isnt actually in the original 900990"},
		&NoLogAction{},
		&RawAction{`pass`, ``},
		&SetVarAction{
			variable:        "tx.crs_setup_version",
			operator:        set,
			value:           "300",
			varMacroMatches: nil,
			valMacroMatches: nil,
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

	expectedTargets := []Target{{Name: `REQUEST_COOKIES`}, {Name: `REQUEST_COOKIES_NAMES`}, {Name: `ARGS_NAMES`}, {Name: `ARGS`}, {Name: `XML`, Selector: "/*"}}
	if len(r.Predicate.Targets) != len(expectedTargets) {
		t.Fatalf("Unexpected targets count. Actual: %d. Expected: %d.", len(r.Predicate.Targets), len(expectedTargets))
	}
	for i := range expectedTargets {
		if r.Predicate.Targets[i] != expectedTargets[i] {
			t.Fatalf("Unexpected target. Actual: %v. Expected: %v.", r.Predicate.Targets[i], expectedTargets[i])
		}
	}

	expectedExceptTargets := []Target{{Name: `REQUEST_COOKIES`, Selector: "__utm", IsRegexSelector: true}}
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

	expectedVal := `(?i:(?:procedure\s+analyse\s*?\()|(?:;\s*?(declare|open)\s+[\w-]+)|(?:create\s+(procedure|function)\s*?\w+\s*?\(\s*?\)\s*?-)|(?:declare[^\w]+[@#]\s*?\w+)|(exec\s*?\(\s*?@))`
	if r.Predicate.Val != expectedVal {
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
		&MsgAction{Msg: "Detects MySQL and PostgreSQL stored procedure/function injections"},
		&RawAction{`tag`, `application-multi`},
		&RawAction{`tag`, `language-multi`},
		&RawAction{`tag`, `platform-multi`},
		&RawAction{`tag`, `attack-sqli`},
		&RawAction{`tag`, `OWASP_CRS/WEB_ATTACK/SQL_INJECTION`},
		&RawAction{`tag`, `WASCTC/WASC-19`},
		&RawAction{`tag`, `OWASP_TOP_10/A1`},
		&RawAction{`tag`, `OWASP_AppSensor/CIE1`},
		&RawAction{`tag`, `PCI/6.5.2`},
		&RawAction{`logdata`, `Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}`},
		&RawAction{`severity`, `CRITICAL`},
		&SetVarAction{
			variable:        "tx.msg",
			operator:        set,
			value:           "%{rule.msg}",
			varMacroMatches: nil,
			valMacroMatches: [][]string{{"%{rule.msg}", "rule.msg"}},
		},
		&SetVarAction{
			variable:        "tx.sql_injection_score",
			operator:        increment,
			value:           "%{tx.critical_anomaly_score}",
			varMacroMatches: nil,
			valMacroMatches: [][]string{{"%{tx.critical_anomaly_score}", "tx.critical_anomaly_score"}},
		},
		&SetVarAction{
			variable:        "tx.anomaly_score",
			operator:        increment,
			value:           "%{tx.critical_anomaly_score}",
			varMacroMatches: nil,
			valMacroMatches: [][]string{{"%{tx.critical_anomaly_score}", "tx.critical_anomaly_score"}},
		},

		&SetVarAction{
			variable:        "tx.%{rule.id}-OWASP_CRS/WEB_ATTACK/SQLI-%{matched_var_name}",
			operator:        set,
			value:           "%{tx.0}",
			varMacroMatches: [][]string{{"%{rule.id}", "rule.id"}, {"%{matched_var_name}", "matched_var_name"}},
			valMacroMatches: [][]string{{"%{tx.0}", "tx.0"}},
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

	expectedTargets := []Target{{Name: "TX", Selector: "crs_setup_version", IsCount: true}}
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

	expectedVal := `0`
	if r.Predicate.Val != expectedVal {
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
		&MsgAction{Msg: ""},
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
				variable:        "tx.anomaly_score",
				operator:        set,
				value:           "123",
				varMacroMatches: nil,
				valMacroMatches: nil,
			},
		},
		{
			`tx.anomaly_score=+123`,
			SetVarAction{
				variable:        "tx.anomaly_score",
				operator:        increment,
				value:           "123",
				varMacroMatches: nil,
				valMacroMatches: nil,
			},
		},
		{
			`tx.anomaly_score=-123`,
			SetVarAction{
				variable:        "tx.anomaly_score",
				operator:        decrement,
				value:           "123",
				varMacroMatches: nil,
				valMacroMatches: nil,
			},
		},
		{
			`!tx.anomaly_score`,
			SetVarAction{
				variable:        "tx.anomaly_score",
				operator:        deleteVar,
				value:           "1",
				varMacroMatches: nil,
				valMacroMatches: nil,
			},
		},
		{
			`tx.anomaly_score=+%{tx.critical_anomaly_score}`,
			SetVarAction{
				variable:        "tx.anomaly_score",
				operator:        increment,
				value:           "%{tx.critical_anomaly_score}",
				varMacroMatches: nil,
				valMacroMatches: [][]string{{"%{tx.critical_anomaly_score}", "tx.critical_anomaly_score"}},
			},
		},
		{
			`tx.anomaly_score=%{tx.critical_anomaly_score} %{tx.something}`,
			SetVarAction{
				variable:        "tx.anomaly_score",
				operator:        set,
				value:           "%{tx.critical_anomaly_score} %{tx.something}",
				varMacroMatches: nil,
				valMacroMatches: [][]string{
					{"%{tx.critical_anomaly_score}", "tx.critical_anomaly_score"},
					{"%{tx.something}", "tx.something"},
				},
			},
		},
		{
			`%{tx.something}=+%{tx.critical_anomaly_score}`,
			SetVarAction{
				variable:        "%{tx.something}",
				operator:        increment,
				value:           "%{tx.critical_anomaly_score}",
				varMacroMatches: [][]string{{"%{tx.something}", "tx.something"}},
				valMacroMatches: [][]string{{"%{tx.critical_anomaly_score}", "tx.critical_anomaly_score"}},
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
