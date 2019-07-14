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
	rr, err := p.Parse(rules, nil)

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
	rr, err := p.Parse(rules, nil)

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
	rr, err := p.Parse(rules, nil)

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
	rr, err := p.Parse(rules, nil)

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
	rr, err := p.Parse(rules, nil)

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
	rr, err := p.Parse(rules, nil)

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
	rr, err := p.Parse(rules, nil)

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
	rr, err := p.Parse(rules, nil)

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
	rr, err := p.Parse(rules, nil)

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
		expected []string
	}
	tests := []testcase{
		{`ARGS|ARGS_NAMES`, []string{`ARGS`, `ARGS_NAMES`}},
		{`ARGS,ARGS_NAMES`, []string{`ARGS`, `ARGS_NAMES`}},
		{`ARGS:/helloworld/`, []string{`ARGS:/helloworld/`}},
		{`ARGS|ARGS:/helloworld/|ARGS_NAMES`, []string{`ARGS`, `ARGS:/helloworld/`, `ARGS_NAMES`}},
		{`ARGS,ARGS:/helloworld/,ARGS_NAMES`, []string{`ARGS`, `ARGS:/helloworld/`, `ARGS_NAMES`}},
		{`ARGS|REQUEST_COOKIES:/S?SESS[a-f0-9]+/|ARGS_NAMES`, []string{`ARGS`, `REQUEST_COOKIES:/S?SESS[a-f0-9]+/`, `ARGS_NAMES`}},
		{`REQUEST_HEADERS:X.Filename`, []string{`REQUEST_HEADERS:X.Filename`}},
		{`"ARGS|ARGS_NAMES"`, []string{`ARGS`, `ARGS_NAMES`}},
		{`"ARGS,ARGS_NAMES"`, []string{`ARGS`, `ARGS_NAMES`}},
		{`"ARGS:'helloworld'"`, []string{`ARGS:'helloworld'`}},
		{`"ARGS:'hello world'"`, []string{`ARGS:'hello world'`}},
		{`"ARGS:'hello \"world'"`, []string{`ARGS:'hello "world'`}},
		{`"ARGS:'hello \\'world'"`, []string{`ARGS:'hello \'world'`}},
		{`"ARGS|ARGS:'helloworld'|ARGS_NAMES"`, []string{`ARGS`, `ARGS:'helloworld'`, `ARGS_NAMES`}},
		{`"ARGS,ARGS:'helloworld',ARGS_NAMES"`, []string{`ARGS`, `ARGS:'helloworld'`, `ARGS_NAMES`}},
		{`"REQUEST_HEADERS:X.Filename"`, []string{`REQUEST_HEADERS:X.Filename`}},
		{`'ARGS|ARGS_NAMES'`, []string{`ARGS`, `ARGS_NAMES`}},
		{`'ARGS:\'helloworld\''`, []string{`ARGS:'helloworld'`}},
		{`'ARGS:\'hello world\''`, []string{`ARGS:'hello world'`}},
		{`'ARGS:\'hello "world\''`, []string{`ARGS:'hello "world'`}},
		{`'ARGS:\'hello \\\'world\''`, []string{`ARGS:'hello \'world'`}},
		{`'ARGS|ARGS:\'helloworld\'|ARGS_NAMES'`, []string{`ARGS`, `ARGS:'helloworld'`, `ARGS_NAMES`}},
		{`XML:/abc|ARGS`, []string{`XML:/abc`, `ARGS`}},
		{`XML:/abc,ARGS`, []string{`XML:/abc`, `ARGS`}},
		{`XML:/*|ARGS`, []string{`XML:/*`, `ARGS`}},
		{`XML:/*,ARGS`, []string{`XML:/*`, `ARGS`}},
		{`'REQUEST_HEADERS:X.Filename'`, []string{`REQUEST_HEADERS:X.Filename`}},
		{`ARGS:list[select]|ARGS_NAMES`, []string{`ARGS:list[select]`, `ARGS_NAMES`}},
		{`ARGS:'list[select]'|ARGS_NAMES`, []string{`ARGS:'list[select]'`, `ARGS_NAMES`}},
		{`ARGS:/abc[0-9]/|ARGS_NAMES`, []string{`ARGS:/abc[0-9]/`, `ARGS_NAMES`}},
		{`"ARGS| ARGS_NAMES"`, []string{`ARGS`, `ARGS_NAMES`}},
		{"\"ARGS| \\\nARGS_NAMES\"", []string{`ARGS`, `ARGS_NAMES`}},
	}

	// Act and assert
	var b strings.Builder
	for _, test := range tests {
		rr, err := p.Parse("SecRule "+test.input+` "<script>" "id:'950902'"`, nil)

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
				fmt.Fprintf(&b, "Wrong target: %s. Tested input: %s\n", r.Items[0].Predicate.Targets[i], test.input)
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
		expectedTargets       []string
		expectedExceptTargets []string
	}
	tests := []testcase{
		{`ARGS|!ARGS:aaa`, []string{`ARGS`}, []string{`ARGS:aaa`}},
		{`!ARGS:aaa|ARGS`, []string{`ARGS`}, []string{`ARGS:aaa`}},
		{`ARGS|!ARGS:aaa|ARGS_NAMES`, []string{`ARGS`, `ARGS_NAMES`}, []string{`ARGS:aaa`}},
		{`ARGS|!ARGS:/aaa./`, []string{`ARGS`}, []string{`ARGS:/aaa./`}},
		{`ARGS|!ARGS:/aaa./|ARGS_NAMES`, []string{`ARGS`, `ARGS_NAMES`}, []string{`ARGS:/aaa./`}},
	}

	// Act and assert
	var b strings.Builder
	for _, test := range tests {
		rr, err := p.Parse("SecRule "+test.input+` "<script>" "id:'950902'"`, nil)

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
				fmt.Fprintf(&b, "Wrong target: %s. Tested input: %s\n", r.Items[0].Predicate.Targets[i], test.input)
			}
		}

		n = len(r.Items[0].Predicate.ExceptTargets)
		if n != len(test.expectedExceptTargets) {
			fmt.Fprintf(&b, "Wrong target exclusions count: %d. Tested input: %s\n", n, test.input)
			continue
		}

		for i, val := range test.expectedExceptTargets {
			if r.Items[0].Predicate.ExceptTargets[i] != val {
				fmt.Fprintf(&b, "Wrong target exclusion: %s. Tested input: %s\n", r.Items[0].Predicate.ExceptTargets[i], test.input)
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
		_, err := p.Parse("SecRule "+test.input+` "<script>" "id:'950902'"`, nil)

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
		rr, err := p.Parse("SecRule ARGS "+test.input+` "id:'950902'"`, nil)

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

func TestSecRuleRawActions(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	type testcase struct {
		input    string
		expected []RawAction
	}
	tests := []testcase{
		{`ID:950902`, []RawAction{{`id`, `950902`}}},
		{`id:950902`, []RawAction{{`id`, `950902`}}},
		{`id:'950902'`, []RawAction{{`id`, `950902`}}},
		{`id:'950902',deny`, []RawAction{{`id`, `950902`}, {`deny`, ``}}},
		{`"id:'950902'"`, []RawAction{{`id`, `950902`}}},
		{`"id:'950902',deny"`, []RawAction{{`id`, `950902`}, {`deny`, ``}}},
		{`"   id:'950902',deny"`, []RawAction{{`id`, `950902`}, {`deny`, ``}}},
		{`'id:\'950902\''`, []RawAction{{`id`, `950902`}}},
		{`'id:\'950902\',deny'`, []RawAction{{`id`, `950902`}, {`deny`, ``}}},
		{`"id:'950902',deny,msg:'Hello World Attack'"`, []RawAction{{`id`, `950902`}, {`deny`, ``}, {`msg`, `Hello World Attack`}}},
		{`"id:950902,setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}"`, []RawAction{{`id`, `950902`}, {`setvar`, `tx.sql_injection_score=+%{tx.critical_anomaly_score}`}}},
		{`"id:'950902',setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}'"`, []RawAction{{`id`, `950902`}, {`setvar`, `tx.sql_injection_score=+%{tx.critical_anomaly_score}`}}},
		{`"id:'950902',logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}'"`, []RawAction{{`id`, `950902`}, {`logdata`, `Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}`}}},
	}

	// Act and assert
	var b strings.Builder
	for _, test := range tests {
		rr, err := p.Parse("SecRule ARGS helloworld "+test.input, nil)

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

		n = len(r.Items[0].RawActions)
		if n != len(test.expected) {
			fmt.Fprintf(&b, "Wrong actions count: %d. Tested input: %s\n", n, test.input)
			continue
		}

		for i, expectedVal := range test.expected {
			a := r.Items[0].RawActions[i]

			if a != expectedVal {
				fmt.Fprintf(&b, "Got wrong action: %s. Expected: %s. Tested input: %s\n", a, expectedVal, test.input)
			}
		}
	}

	if b.Len() > 0 {
		t.Fatalf("\n%s", b.String())
	}
}

func TestTransformationCaseInsensitive(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rule := `
		SecRule ARGS "helloworld" "t:cssDecode,t:UrLdEcOdEuNi,id:942320"
	`

	// Act
	rr, err := p.Parse(rule, nil)

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
	rr, err := p.Parse(rule, nil)

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

	expectedMsg := "this message isnt actually in the original 900990"
	if a.Msg != expectedMsg {
		t.Fatalf("Unexpected Msg. Actual: %s. Expected: %s.", a.Msg, expectedMsg)
	}

	expectedRawActions := []RawAction{
		{`id`, `900990`},
		{`msg`, `this message isnt actually in the original 900990`},
		{`phase`, `1`},
		{`nolog`, ``},
		{`pass`, ``},
		{`t`, `none`},
		{`setvar`, `tx.crs_setup_version=300`},
	}
	if len(a.RawActions) != len(expectedRawActions) {
		t.Fatalf("Unexpected raw actions count. Actual: %d. Expected: %d.", len(a.RawActions), len(expectedRawActions))
	}
	for i := range expectedRawActions {
		if a.RawActions[i] != expectedRawActions[i] {
			t.Fatalf("Unexpected raw action. Actual: %s. Expected: %s.", a.RawActions[i], expectedRawActions[i])
		}
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
	rr, err := p.Parse(rule, nil)

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

	expectedMsg := "Detects MySQL and PostgreSQL stored procedure/function injections"
	if r.Msg != expectedMsg {
		t.Fatalf("Unexpected Msg. Actual: %s. Expected: %s.", r.Msg, expectedMsg)
	}

	expectedTargets := []string{`REQUEST_COOKIES`, `REQUEST_COOKIES_NAMES`, `ARGS_NAMES`, `ARGS`, `XML:/*`}
	if len(r.Predicate.Targets) != len(expectedTargets) {
		t.Fatalf("Unexpected targets count. Actual: %d. Expected: %d.", len(r.Predicate.Targets), len(expectedTargets))
	}
	for i := range expectedTargets {
		if r.Predicate.Targets[i] != expectedTargets[i] {
			t.Fatalf("Unexpected target. Actual: %s. Expected: %s.", r.Predicate.Targets[i], expectedTargets[i])
		}
	}

	expectedExceptTargets := []string{`REQUEST_COOKIES:/__utm/`}
	if len(r.Predicate.ExceptTargets) != len(expectedExceptTargets) {
		t.Fatalf("Unexpected except-targets count. Actual: %d. Expected: %d.", len(r.Predicate.ExceptTargets), len(expectedExceptTargets))
	}
	for i := range expectedExceptTargets {
		if r.Predicate.ExceptTargets[i] != expectedExceptTargets[i] {
			t.Fatalf("Unexpected except-targets. Actual: %s. Expected: %s.", r.Predicate.ExceptTargets[i], expectedExceptTargets[i])
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

	expectedRawActions := []RawAction{
		{`phase`, `request`},
		{`rev`, `2`},
		{`ver`, `OWASP_CRS/3.0.0`},
		{`maturity`, `9`},
		{`accuracy`, `8`},
		{`capture`, ``},
		{`t`, `none`},
		{`t`, `urlDecodeUni`},
		{`block`, ``},
		{`msg`, `Detects MySQL and PostgreSQL stored procedure/function injections`},
		{`id`, `942320`},
		{`tag`, `application-multi`},
		{`tag`, `language-multi`},
		{`tag`, `platform-multi`},
		{`tag`, `attack-sqli`},
		{`tag`, `OWASP_CRS/WEB_ATTACK/SQL_INJECTION`},
		{`tag`, `WASCTC/WASC-19`},
		{`tag`, `OWASP_TOP_10/A1`},
		{`tag`, `OWASP_AppSensor/CIE1`},
		{`tag`, `PCI/6.5.2`},
		{`logdata`, `Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}`},
		{`severity`, `CRITICAL`},
		{`setvar`, `tx.msg=%{rule.msg}`},
		{`setvar`, `tx.sql_injection_score=+%{tx.critical_anomaly_score}`},
		{`setvar`, `tx.anomaly_score=+%{tx.critical_anomaly_score}`},
		{`setvar`, `tx.%{rule.id}-OWASP_CRS/WEB_ATTACK/SQLI-%{matched_var_name}=%{tx.0}`},
	}
	if len(r.RawActions) != len(expectedRawActions) {
		t.Fatalf("Unexpected raw actions count. Actual: %d. Expected: %d.", len(r.RawActions), len(expectedRawActions))
	}
	for i := range expectedRawActions {
		if r.RawActions[i] != expectedRawActions[i] {
			t.Fatalf("Unexpected raw action. Actual: %s. Expected: %s.", r.RawActions[i], expectedRawActions[i])
		}
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
        msg:'ModSecurity Core Rule Set is deployed without configuration! Please copy the crs-setup.conf.example template to crs-setup.conf, and include the crs-setup.conf file in your webserver configuration before including the CRS rules. See the INSTALL file in the CRS directory for detailed instructions.'"
    `

	// Act
	rr, err := p.Parse(rule, nil)

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

	expectedMsg := "ModSecurity Core Rule Set is deployed without configuration! Please copy the crs-setup.conf.example template to crs-setup.conf, and include the crs-setup.conf file in your webserver configuration before including the CRS rules. See the INSTALL file in the CRS directory for detailed instructions."
	if r.Msg != expectedMsg {
		t.Fatalf("Unexpected Msg. Actual: %s. Expected: %s.", r.Msg, expectedMsg)
	}

	expectedTargets := []string{`&TX:crs_setup_version`}
	if len(r.Predicate.Targets) != len(expectedTargets) {
		t.Fatalf("Unexpected targets count. Actual: %d. Expected: %d.", len(r.Predicate.Targets), len(expectedTargets))
	}
	for i := range expectedTargets {
		if r.Predicate.Targets[i] != expectedTargets[i] {
			t.Fatalf("Unexpected target. Actual: %s. Expected: %s.", r.Predicate.Targets[i], expectedTargets[i])
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

	expectedRawActions := []RawAction{
		{`id`, `901001`},
		{`phase`, `1`},
		{`auditlog`, ``},
		{`log`, ``},
		{`deny`, ``},
		{`status`, `500`},
		{`severity`, `CRITICAL`},
		{`msg`, `ModSecurity Core Rule Set is deployed without configuration! Please copy the crs-setup.conf.example template to crs-setup.conf, and include the crs-setup.conf file in your webserver configuration before including the CRS rules. See the INSTALL file in the CRS directory for detailed instructions.`},
	}
	if len(r.RawActions) != len(expectedRawActions) {
		t.Fatalf("Unexpected raw actions count. Actual: %d. Expected: %d.", len(r.RawActions), len(expectedRawActions))
	}
	for i := range expectedRawActions {
		if r.RawActions[i] != expectedRawActions[i] {
			t.Fatalf("Unexpected raw action. Actual: %s. Expected: %s.", r.RawActions[i], expectedRawActions[i])
		}
	}

	expectedTransformations := []Transformation{URLDecodeUni}
	if len(r.Transformations) != 0 {
		t.Fatalf("Unexpected transformations count. Actual: %d. Expected: %d.", len(r.Transformations), len(expectedTransformations))
	}
}

func TestPhraseFunc(t *testing.T) {
	callbackArg := ""
	p := NewRuleParser()
	_, err := p.Parse(`SecRule ARGS "@pmf test.data" "deny,msg:'SQL Injection Attack',id:'950901'"`, func(f string) ([]string, error) {
		callbackArg = f
		return []string{}, nil
	})

	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if callbackArg != "test.data" {
		t.Fatalf("...")
	}
}

func TestNolog(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rule := `SecRule ARGS "hello" "id:901001,nolog"`

	// Act
	rr, err := p.Parse(rule, nil)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	rc, ok := rr[0].(*Rule)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	if !rc.Nolog {
		t.Fatalf("Nolog not set")
	}
}

func TestNologChain(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rule := `
		SecRule ARGS "hello" "id:901001,chain"
		SecRule ARGS "abc" "nolog"
	`

	// Act
	rr, err := p.Parse(rule, nil)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	rc, ok := rr[0].(*Rule)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	if !rc.Nolog {
		t.Fatalf("Nolog not set")
	}
}

func TestNologChain910130(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rule := `
		SecRule &TX:block_suspicious_ip "@eq 0" \
		  "id:910130,\
		  phase:request,\
		  t:none,\
		  nolog,\
		  pass,\
		  chain,\
		  skipAfter:END_RBL_CHECK"
		  SecRule &TX:block_harvester_ip "@eq 0" "chain"
		  SecRule &TX:block_spammer_ip "@eq 0" "chain"
		  SecRule &TX:block_search_ip "@eq 0"
	`

	// Act
	rr, err := p.Parse(rule, nil)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	rc, ok := rr[0].(*Rule)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	if !rc.Nolog {
		t.Fatalf("Nolog not set")
	}
}

func TestNologNegative(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rule := `SecRule ARGS "hello" "id:901001,deny"`

	// Act
	rr, err := p.Parse(rule, nil)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	rc, ok := rr[0].(*Rule)
	if !ok {
		t.Fatalf("Wrong statement type: %T", rr[0])
	}

	if rc.Nolog {
		t.Fatalf("Nolog set")
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
	rr, err := p.Parse(rule, nil)

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
	rr, err := p.Parse(rule, nil)

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
	rr, err := p.Parse(rule, nil)

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
	_, err := p.Parse(rule, nil)

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
	rr, err := p.Parse(rule, nil)

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
	rr, err := p.Parse(rule, nil)

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
		if a, ok := a.(*skipAfterAction); ok {
			found = true
			if a.label != "somelabel" {
				t.Fatalf("Unexpected label: %v", a.label)
			}
		}
	}

	if !found {
		t.Fatalf("Did not find skipAfter action")
	}
}
