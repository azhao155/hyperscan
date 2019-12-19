package ruleparsing

import (
	. "azwaf/secrule/ast"

	"testing"
)

func TestparseSetVarActionDefaultAssignment(t *testing.T) {
	param := "ip.reput_block_flag"
	sv, err := parseSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if !sv.Variable.Equal(Value{StringToken("ip.reput_block_flag")}) {
		t.Fatalf("Got unexpected variable: %s", sv.Variable)
	}

	if sv.Operator != Set {
		t.Fatalf("Got unexpected operator: %d", sv.Operator)
	}

	if !sv.Value.Equal(Value{IntToken(1)}) {
		t.Fatalf("Got unexpected value: %s", sv.Value)
	}
}

func TestparseSetVarActionNumericAssignment(t *testing.T) {
	param := "ip.reput_block_flag=1"
	sv, err := parseSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if !sv.Variable.Equal(Value{StringToken("ip.reput_block_flag")}) {
		t.Fatalf("Got unexpected variable: %s", sv.Variable)
	}

	if sv.Operator != Set {
		t.Fatalf("Got unexpected operator: %d", sv.Operator)
	}

	if !sv.Value.Equal(Value{IntToken(1)}) {
		t.Fatalf("Got unexpected value: %s", sv.Value)
	}

	param = "tx.php_injection_score=+%{tx.critical_anomaly_score}"
	sv, err = parseSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if !sv.Variable.Equal(Value{StringToken("tx.php_injection_score")}) {
		t.Fatalf("Got unexpected variable: %s", sv.Variable)
	}

	if sv.Operator != Increment {
		t.Fatalf("Got unexpected operator: %d", sv.Operator)
	}

	if !sv.Value.Equal(Value{MacroToken{Name: EnvVarTx, Selector: "critical_anomaly_score"}}) {
		t.Fatalf("Got unexpected value: %s", sv.Value)
	}
}

func TestparseSetVarActionStringAssignment(t *testing.T) {
	param := "tx.sqli_select_statement=%{tx.sqli_select_statement} %{matched_var}"
	sv, err := parseSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if !sv.Variable.Equal(Value{StringToken("tx.sqli_select_statement")}) {
		t.Fatalf("Got unexpected variable: %s", sv.Variable)
	}

	if sv.Operator != Set {
		t.Fatalf("Got unexpected operator: %d", sv.Operator)
	}

	if !sv.Value.Equal(Value{MacroToken{Name: EnvVarTx, Selector: "sqli_select_statement"}, MacroToken{Name: EnvVarMatchedVar}}) {
		t.Fatalf("Got unexpected value: %s", sv.Value)
	}
}

func TestparseSetVarActionDeletion(t *testing.T) {
	param := "!ip.reput_block_flag"
	sv, err := parseSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if !sv.Variable.Equal(Value{StringToken("ip.reput_block_flag")}) {
		t.Fatalf("Got unexpected variable: %s", sv.Variable)
	}

	if sv.Operator != DeleteVar {
		t.Fatalf("Got unexpected operator: %d", sv.Operator)
	}
}
