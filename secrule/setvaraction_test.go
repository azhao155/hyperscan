package secrule

import "testing"

func TestparseSetVarActionDefaultAssignment(t *testing.T) {
	param := "ip.reput_block_flag"
	sv, err := parseSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if !sv.variable.equal(Value{StringToken("ip.reput_block_flag")}) {
		t.Fatalf("Got unexpected variable: %s", sv.variable)
	}

	if sv.operator != set {
		t.Fatalf("Got unexpected operator: %d", sv.operator)
	}

	if !sv.value.equal(Value{IntToken(1)}) {
		t.Fatalf("Got unexpected value: %s", sv.value)
	}
}

func TestparseSetVarActionNumericAssignment(t *testing.T) {
	param := "ip.reput_block_flag=1"
	sv, err := parseSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if !sv.variable.equal(Value{StringToken("ip.reput_block_flag")}) {
		t.Fatalf("Got unexpected variable: %s", sv.variable)
	}

	if sv.operator != set {
		t.Fatalf("Got unexpected operator: %d", sv.operator)
	}

	if !sv.value.equal(Value{IntToken(1)}) {
		t.Fatalf("Got unexpected value: %s", sv.value)
	}

	param = "tx.php_injection_score=+%{tx.critical_anomaly_score}"
	sv, err = parseSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if !sv.variable.equal(Value{StringToken("tx.php_injection_score")}) {
		t.Fatalf("Got unexpected variable: %s", sv.variable)
	}

	if sv.operator != increment {
		t.Fatalf("Got unexpected operator: %d", sv.operator)
	}

	if !sv.value.equal(Value{MacroToken{Name: EnvVarTx, Selector: "critical_anomaly_score"}}) {
		t.Fatalf("Got unexpected value: %s", sv.value)
	}
}

func TestparseSetVarActionStringAssignment(t *testing.T) {
	param := "tx.sqli_select_statement=%{tx.sqli_select_statement} %{matched_var}"
	sv, err := parseSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if !sv.variable.equal(Value{StringToken("tx.sqli_select_statement")}) {
		t.Fatalf("Got unexpected variable: %s", sv.variable)
	}

	if sv.operator != set {
		t.Fatalf("Got unexpected operator: %d", sv.operator)
	}

	if !sv.value.equal(Value{MacroToken{Name: EnvVarTx, Selector: "sqli_select_statement"}, MacroToken{Name: EnvVarMatchedVar}}) {
		t.Fatalf("Got unexpected value: %s", sv.value)
	}
}

func TestparseSetVarActionDeletion(t *testing.T) {
	param := "!ip.reput_block_flag"
	sv, err := parseSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if !sv.variable.equal(Value{StringToken("ip.reput_block_flag")}) {
		t.Fatalf("Got unexpected variable: %s", sv.variable)
	}

	if sv.operator != deleteVar {
		t.Fatalf("Got unexpected operator: %d", sv.operator)
	}
}

func TestSetvarActionExecuteAssignment(t *testing.T) {
	param := "tx.somevar=1"
	sv, err := parseSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	perReqState := newEnvironment(nil)
	if err = executeSetVarAction(&sv, perReqState); err != nil {
		t.Fatalf("Unexpected error during execute %s", err)
	}

	val := perReqState.get(EnvVarTx, "somevar")
	if val == nil {
		t.Fatalf("Per request state key: tx.somevar not found")
	}

	if !val.equal(Value{IntToken(1)}) {
		t.Fatalf("Unexpected per request state key: tx.somevar, value: %s", val)
	}
}

func TestSetvarActionExecuteIncrement(t *testing.T) {
	param := "tx.somevar=+1"
	sv, err := parseSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	perReqState := newEnvironment(nil)
	perReqState.set(EnvVarTx, "somevar", Value{IntToken(1)})

	if err = executeSetVarAction(&sv, perReqState); err != nil {
		t.Fatalf("Unexpected error during execute %s", err)
	}

	val := perReqState.get(EnvVarTx, "somevar")

	if val == nil {
		t.Fatalf("Per request state key: tx.somevar not found")
	}

	if !val.equal(Value{IntToken(2)}) {
		t.Fatalf("Unexpected per request state key: tx.somevar, value: %s", val.string())
	}
}

func TestSetvarActionExecuteDecrement(t *testing.T) {
	param := "tx.somevar=-1"
	sv, err := parseSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	perReqState := newEnvironment(nil)
	perReqState.set(EnvVarTx, "somevar", Value{IntToken(5)})

	if err = executeSetVarAction(&sv, perReqState); err != nil {
		t.Fatalf("Unexpected error during execute %s", err)
	}

	val := perReqState.get(EnvVarTx, "somevar")
	if val == nil {
		t.Fatalf("Per request state key: tx.somevar not found")
	}

	if !val.equal(Value{IntToken(4)}) {
		t.Fatalf("Unexpected per request state key: tx.somevar, value: %s", val.string())
	}
}

func TestSetvarActionExecuteDelete(t *testing.T) {
	param := "!tx.somevar"
	sv, err := parseSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	perReqState := newEnvironment(nil)
	perReqState.set(EnvVarTx, "somevar", Value{IntToken(5)})

	if err := executeSetVarAction(&sv, perReqState); err != nil {
		t.Fatalf("Unexpected error during execute %s", err)
	}

	if v := perReqState.get(EnvVarTx, "somevar"); v != nil {
		t.Fatalf("Per request state key: tx.somevar should have been deleted")
	}
}

func TestSetvarActionExecuteExpandVars(t *testing.T) {
	param := "tx.anomaly_score=+%{tx.critical_anomaly_score}"
	sv, err := parseSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	perReqState := newEnvironment(nil)
	perReqState.set(EnvVarTx, "anomaly_score", Value{IntToken(15)})
	perReqState.set(EnvVarTx, "critical_anomaly_score", Value{IntToken(5)})

	if err := executeSetVarAction(&sv, perReqState); err != nil {
		t.Fatalf("Unexpected error during execute %s", err)
	}

	val := perReqState.get(EnvVarTx, "anomaly_score")
	if val == nil {
		t.Fatalf("Per request state key: tx.anomaly_score not found")

	}

	if !val.equal(Value{IntToken(20)}) {
		t.Fatalf("Unexpected per request state key: tx.anomaly_score, value: %s", val)
	}
}
