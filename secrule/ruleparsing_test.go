package secrule

import (
	"fmt"
	"strings"
	"testing"
)

// Unit tests that only know the ruleParser interface. More "black box" than ruleparsing_impl_test.go.

func TestTwoRules(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rules := `
		SecRule ARGS "1=1" "deny,msg:'SQL Injection Attack',id:'950901'"
		SecRule ARGS "<script>" "deny,msg:'XSS Attack',id:'950902'"
	`

	// Act
	rr, err := p.Parse(rules)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if len(rr) != 2 {
		t.Fatalf("Wrong rule rules count: %d", len(rr))
	}

	r := rr[0]
	if r.ID != 950901 {
		t.Fatalf("Wrong ID of 950901")
	}

	r = rr[1]
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
	rr, err := p.Parse(rules)

	// Assert
	if err == nil {
		t.Fatalf("Expected error, but err was nil")
	}

	if err.Error() != "Unknown statement on line 9: Something something something" {
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
	rr, err := p.Parse(rules)

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
	rr, err := p.Parse(rules)

	// Assert
	if len(rr) != 0 {
		t.Fatalf("Wrong rule rules count: %d", len(rr))
	}

	if err == nil {
		t.Fatalf("Expected error, but err was nil")
	}

	expected := "Parse error in SecRule on line 2: Missing ID"
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
	rr, err := p.Parse(rules)

	// Assert
	if len(rr) != 0 {
		t.Fatalf("Wrong rule rules count: %d", len(rr))
	}

	if err == nil {
		t.Fatalf("Expected error, but err was nil")
	}

	expected := "Parse error in SecRule on line 2: Unexpected arg: something"
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
	rr, err := p.Parse(rules)

	// Assert
	if len(rr) != 1 {
		t.Fatalf("Wrong rule rules count: %d", len(rr))
	}

	if err == nil {
		t.Fatalf("Expected error, but err was nil")
	}

	expected := "Parse error in SecRule on line 4: Missing ID"
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
	rr, err := p.Parse(rules)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	n := len(rr)
	if n != 3 {
		t.Fatalf("Wrong rule rules count: %d", n)
	}

	n = len(rr[0].Items)
	if n != 1 {
		t.Fatalf("Wrong rule items count in rule 0: %d", n)
	}

	n = len(rr[1].Items)
	if len(rr[1].Items) != 3 {
		t.Fatalf("Wrong rule items count in rule 1: %d", n)
	}

	n = len(rr[2].Items)
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
	rr, err := p.Parse(rules)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	n := len(rr)
	if n != 1 {
		t.Fatalf("Wrong rules count: %d", n)
	}

	n = len(rr[0].Items)
	if n != 2 {
		t.Fatalf("Wrong rule items count in rule 0: %d", n)
	}
}

func TestSecRuleTargets(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	type testcase struct {
		input       string
		expected    []string
		expectedErr string
	}
	tests := []testcase{
		testcase{`ARGS|ARGS_NAMES`, []string{`ARGS`, `ARGS_NAMES`}, ``},
		testcase{`ARGS:/helloworld/`, []string{`ARGS:/helloworld/`}, ``},
		testcase{`ARGS|ARGS:/helloworld/|ARGS_NAMES`, []string{`ARGS`, `ARGS:/helloworld/`, `ARGS_NAMES`}, ``},
		testcase{`"ARGS|ARGS_NAMES"`, []string{`ARGS`, `ARGS_NAMES`}, ``},
		testcase{`"ARGS:'helloworld'"`, []string{`ARGS:'helloworld'`}, ``},
		testcase{`"ARGS:'hello world'"`, []string{`ARGS:'hello world'`}, ``},
		testcase{`"ARGS:'hello \"world'"`, []string{`ARGS:'hello "world'`}, ``},
		testcase{`"ARGS:'hello \\'world'"`, []string{`ARGS:'hello \'world'`}, ``},
		testcase{`"ARGS|ARGS:'helloworld'|ARGS_NAMES"`, []string{`ARGS`, `ARGS:'helloworld'`, `ARGS_NAMES`}, ``},
		testcase{`'ARGS|ARGS_NAMES'`, []string{`ARGS`, `ARGS_NAMES`}, ``},
		testcase{`'ARGS:\'helloworld\''`, []string{`ARGS:'helloworld'`}, ``},
		testcase{`'ARGS:\'hello world\''`, []string{`ARGS:'hello world'`}, ``},
		testcase{`'ARGS:\'hello "world\''`, []string{`ARGS:'hello "world'`}, ``},
		testcase{`'ARGS:\'hello \\\'world\''`, []string{`ARGS:'hello \'world'`}, ``},
		testcase{`'ARGS|ARGS:\'helloworld\'|ARGS_NAMES'`, []string{`ARGS`, `ARGS:'helloworld'`, `ARGS_NAMES`}, ``},
		testcase{`"ARGS| ARGS_NAMES"`, []string{`ARGS`, `ARGS_NAMES`}, ``},
		testcase{"\"ARGS| \\\nARGS_NAMES\"", []string{`ARGS`, `ARGS_NAMES`}, ``},
		testcase{`|`, nil, `Parse error in SecRule on line 1: Unable to parse targets`},
	}

	// Act and assert
	var b strings.Builder
	for _, test := range tests {
		rr, err := p.Parse("SecRule " + test.input + ` "<script>" "id:'950902'"`)

		if test.expectedErr != "" {
			if err == nil {
				t.Fatalf("Expected error, but err was nil")
			} else if err.Error() != test.expectedErr {
				fmt.Fprintf(&b, "Error message was not as expected. Expected: %s. Got: %s", test.expectedErr, err)
			}

			continue
		}

		if err != nil {
			fmt.Fprintf(&b, "Got unexpected error: %s. Tested input: %s\n", err, test.input)
			continue
		}

		n := len(rr)
		if n != 1 {
			fmt.Fprintf(&b, "Wrong rules count: %d. Tested input: %s\n", n, test.input)
			continue
		}

		n = len(rr[0].Items)
		if n != 1 {
			fmt.Fprintf(&b, "Wrong rule items count in rule 0: %d. Tested input: %s\n", n, test.input)
			continue
		}

		n = len(rr[0].Items[0].Targets)
		if n != len(test.expected) {
			fmt.Fprintf(&b, "Wrong targets count: %d. Tested input: %s\n", n, test.input)
			continue
		}

		for i, val := range test.expected {
			if rr[0].Items[0].Targets[i] != val {
				fmt.Fprintf(&b, "Wrong target: %s. Tested input: %s\n", rr[0].Items[0].Targets[i], test.input)
			}
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
	}
	tests := []testcase{
		testcase{`helloworld`, Rx, `helloworld`},
		testcase{`"hello world"`, Rx, `hello world`},
		testcase{`"hello \"world"`, Rx, `hello "world`},
		testcase{`"hello 'world"`, Rx, `hello 'world`},
		testcase{`'hello world'`, Rx, `hello world`},
		testcase{`'hello "world'`, Rx, `hello "world`},
		testcase{`"@contains helloworld"`, Contains, `helloworld`},
		testcase{`'@contains helloworld'`, Contains, `helloworld`},
		testcase{`'@detectSQLi'`, DetectSQLi, ``},
		testcase{`'@DeTeCtSqLi'`, DetectSQLi, ``},
	}

	// Act and assert
	var b strings.Builder
	for _, test := range tests {
		rr, err := p.Parse("SecRule ARGS " + test.input + ` "id:'950902'"`)

		if err != nil {
			fmt.Fprintf(&b, "Got unexpected error: %s. Tested input: %s\n", err, test.input)
			continue
		}

		n := len(rr)
		if n != 1 {
			fmt.Fprintf(&b, "Wrong rules count: %d. Tested input: %s\n", n, test.input)
			continue
		}

		n = len(rr[0].Items)
		if n != 1 {
			fmt.Fprintf(&b, "Wrong rule items count in rule 0: %d. Tested input: %s\n", n, test.input)
			continue
		}

		if rr[0].Items[0].Op != test.op {
			fmt.Fprintf(&b, "Wrong Operator: %d. Tested input: %s\n", rr[0].Items[0].Op, test.input)
			continue
		}

		if rr[0].Items[0].Val != test.val {
			fmt.Fprintf(&b, "Wrong value: %s. Tested input: %s\n", rr[0].Items[0].Val, test.input)
			continue
		}
	}

	if b.Len() > 0 {
		t.Fatalf("%s", b.String())
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
		testcase{`id:950902`, []RawAction{{`id`, `950902`}}},
		testcase{`id:'950902'`, []RawAction{{`id`, `950902`}}},
		testcase{`id:'950902',deny`, []RawAction{{`id`, `950902`}, {`deny`, ``}}},
		testcase{`"id:'950902'"`, []RawAction{{`id`, `950902`}}},
		testcase{`"id:'950902',deny"`, []RawAction{{`id`, `950902`}, {`deny`, ``}}},
		testcase{`'id:\'950902\''`, []RawAction{{`id`, `950902`}}},
		testcase{`'id:\'950902\',deny'`, []RawAction{{`id`, `950902`}, {`deny`, ``}}},
		testcase{`"id:'950902',deny,msg:'Hello World Attack'"`, []RawAction{{`id`, `950902`}, {`deny`, ``}, {`msg`, `Hello World Attack`}}},
		testcase{`"id:950902,setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}"`, []RawAction{{`id`, `950902`}, {`setvar`, `tx.sql_injection_score=+%{tx.critical_anomaly_score}`}}},
		testcase{`"id:'950902',setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}'"`, []RawAction{{`id`, `950902`}, {`setvar`, `tx.sql_injection_score=+%{tx.critical_anomaly_score}`}}},
		testcase{`"id:'950902',logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}'"`, []RawAction{{`id`, `950902`}, {`logdata`, `Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}`}}},
	}

	// Act and assert
	var b strings.Builder
	for _, test := range tests {
		rr, err := p.Parse("SecRule ARGS helloworld " + test.input)

		if err != nil {
			fmt.Fprintf(&b, "Got unexpected error: %s. Tested input: %s\n", err, test.input)
			continue
		}

		n := len(rr)
		if n != 1 {
			fmt.Fprintf(&b, "Wrong rules count: %d. Tested input: %s\n", n, test.input)
			continue
		}

		n = len(rr[0].Items)
		if n != 1 {
			fmt.Fprintf(&b, "Wrong rule items count in rule 0: %d. Tested input: %s\n", n, test.input)
			continue
		}

		n = len(rr[0].Items[0].RawActions)
		if n != len(test.expected) {
			fmt.Fprintf(&b, "Wrong actions count: %d. Tested input: %s\n", n, test.input)
			continue
		}

		for i, expectedVal := range test.expected {
			a := rr[0].Items[0].RawActions[i]

			if a != expectedVal {
				fmt.Fprintf(&b, "Got wrong action: %s. Expected: %s. Tested input: %s\n", a, expectedVal, test.input)
			}
		}
	}

	if b.Len() > 0 {
		t.Fatalf("%s", b.String())
	}
}

func TestTransformationCaseInsensitive(t *testing.T) {
	// Arrange
	p := NewRuleParser()
	rule := `
		SecRule ARGS "helloworld" "t:cssDecode,t:UrLdEcOdEuNi,id:942320"
	`

	// Act
	rr, err := p.Parse(rule)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	rc := rr[0]

	if len(rc.Items) != 1 {
		t.Fatalf("Unexpected rule count: %d", len(rc.Items))
	}

	r := rc.Items[0]

	expectedTransformations := []Transformation{CssDecode, UrlDecodeUni}
	if len(r.Transformations) != len(expectedTransformations) {
		t.Fatalf("Unexpected transformations count. Actual: %d. Expected: %d.", len(r.Transformations), len(expectedTransformations))
	}
	for i := range expectedTransformations {
		if r.Transformations[i] != expectedTransformations[i] {
			t.Fatalf("Unexpected transformation. Actual: %d. Expected: %d.", r.Transformations[i], expectedTransformations[i])
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
	rr, err := p.Parse(rule)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	rc := rr[0]

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

	expectedTargets := []string{`REQUEST_COOKIES`, `!REQUEST_COOKIES:/__utm/`, `REQUEST_COOKIES_NAMES`, `ARGS_NAMES`, `ARGS`, `XML:/*`}
	if len(r.Targets) != len(expectedTargets) {
		t.Fatalf("Unexpected targets count. Actual: %d. Expected: %d.", len(r.Targets), len(expectedTargets))
	}
	for i := range expectedTargets {
		if r.Targets[i] != expectedTargets[i] {
			t.Fatalf("Unexpected target. Actual: %s. Expected: %s.", r.Targets[i], expectedTargets[i])
		}
	}

	if r.Op != Rx {
		t.Fatalf("Unexpected Operator: %d", r.Op)
	}

	if r.Neg != false {
		t.Fatalf("Unexpected neg value: %t", r.Neg)
	}

	expectedVal := `(?i:(?:procedure\s+analyse\s*?\()|(?:;\s*?(declare|open)\s+[\w-]+)|(?:create\s+(procedure|function)\s*?\w+\s*?\(\s*?\)\s*?-)|(?:declare[^\w]+[@#]\s*?\w+)|(exec\s*?\(\s*?@))`
	if r.Val != expectedVal {
		t.Fatalf("Unexpected Operator value. Actual: %s. Expected: %s", r.Val, expectedVal)
	}

	expectedRawActions := []RawAction{
		RawAction{`phase`, `request`},
		RawAction{`rev`, `2`},
		RawAction{`ver`, `OWASP_CRS/3.0.0`},
		RawAction{`maturity`, `9`},
		RawAction{`accuracy`, `8`},
		RawAction{`capture`, ``},
		RawAction{`t`, `none`},
		RawAction{`t`, `urlDecodeUni`},
		RawAction{`block`, ``},
		RawAction{`msg`, `Detects MySQL and PostgreSQL stored procedure/function injections`},
		RawAction{`id`, `942320`},
		RawAction{`tag`, `application-multi`},
		RawAction{`tag`, `language-multi`},
		RawAction{`tag`, `platform-multi`},
		RawAction{`tag`, `attack-sqli`},
		RawAction{`tag`, `OWASP_CRS/WEB_ATTACK/SQL_INJECTION`},
		RawAction{`tag`, `WASCTC/WASC-19`},
		RawAction{`tag`, `OWASP_TOP_10/A1`},
		RawAction{`tag`, `OWASP_AppSensor/CIE1`},
		RawAction{`tag`, `PCI/6.5.2`},
		RawAction{`logdata`, `Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}`},
		RawAction{`severity`, `CRITICAL`},
		RawAction{`setvar`, `tx.msg=%{rule.msg}`},
		RawAction{`setvar`, `tx.sql_injection_score=+%{tx.critical_anomaly_score}`},
		RawAction{`setvar`, `tx.anomaly_score=+%{tx.critical_anomaly_score}`},
		RawAction{`setvar`, `tx.%{rule.id}-OWASP_CRS/WEB_ATTACK/SQLI-%{matched_var_name}=%{tx.0}`},
	}
	if len(r.RawActions) != len(expectedRawActions) {
		t.Fatalf("Unexpected raw actions count. Actual: %d. Expected: %d.", len(r.RawActions), len(expectedRawActions))
	}
	for i := range expectedRawActions {
		if r.RawActions[i] != expectedRawActions[i] {
			t.Fatalf("Unexpected raw action. Actual: %s. Expected: %s.", r.RawActions[i], expectedRawActions[i])
		}
	}

	expectedTransformations := []Transformation{UrlDecodeUni}
	if len(r.Transformations) != len(expectedTransformations) {
		t.Fatalf("Unexpected transformations count. Actual: %d. Expected: %d.", len(r.Transformations), len(expectedTransformations))
	}
	for i := range expectedTransformations {
		if r.Transformations[i] != expectedTransformations[i] {
			t.Fatalf("Unexpected transformation. Actual: %d. Expected: %d.", r.Transformations[i], expectedTransformations[i])
		}
	}
}
