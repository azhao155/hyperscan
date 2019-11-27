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

	if !sv.value.equal(Value{MacroToken("tx.critical_anomaly_score")}) {
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

	if !sv.value.equal(Value{MacroToken("tx.sqli_select_statement"), MacroToken("matched_var")}) {
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
	param := "ip.reput_block_flag=1"
	sv, err := parseSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	perReqState := newEnvironment(&ScanResults{})
	if err = executeSetVarAction(&sv, perReqState); err != nil {
		t.Fatalf("Unexpected error during execute %s", err)
	}

	val, ok := perReqState.get("ip.reput_block_flag")
	if !ok {
		t.Fatalf("Per request state key: ip.reput_block_flag not found")
	}

	if !val.equal(Value{IntToken(1)}) {
		t.Fatalf("Unexpected per request state key: ip.reput_block_flag, value: %s", val)
	}
}

func TestSetvarActionExecuteIncrement(t *testing.T) {
	param := "ip.reput_block_flag=+1"
	sv, err := parseSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	perReqState := newEnvironment(&ScanResults{})
	perReqState.set("ip.reput_block_flag", Value{IntToken(1)})

	if err = executeSetVarAction(&sv, perReqState); err != nil {
		t.Fatalf("Unexpected error during execute %s", err)
	}

	val, ok := perReqState.get("ip.reput_block_flag")

	if !ok {
		t.Fatalf("Per request state key: ip.reput_block_flag not found")
	}

	if !val.equal(Value{IntToken(2)}) {
		t.Fatalf("Unexpected per request state key: ip.reput_block_flag, value: %s", val.string())
	}
}

func TestSetvarActionExecuteDecrement(t *testing.T) {
	param := "ip.reput_block_flag=-1"
	sv, err := parseSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	perReqState := newEnvironment(&ScanResults{})
	perReqState.set("ip.reput_block_flag", Value{IntToken(5)})

	if err = executeSetVarAction(&sv, perReqState); err != nil {
		t.Fatalf("Unexpected error during execute %s", err)
	}

	val, ok := perReqState.get("ip.reput_block_flag")
	if !ok {
		t.Fatalf("Per request state key: ip.reput_block_flag not found")
	}

	if !val.equal(Value{IntToken(4)}) {
		t.Fatalf("Unexpected per request state key: ip.reput_block_flag, value: %s", val.string())
	}
}

func TestSetvarActionExecuteDelete(t *testing.T) {
	param := "!ip.reput_block_flag"
	sv, err := parseSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	perReqState := newEnvironment(&ScanResults{})
	perReqState.set("ip.reput_block_flag", Value{IntToken(5)})

	if err := executeSetVarAction(&sv, perReqState); err != nil {
		t.Fatalf("Unexpected error during execute %s", err)
	}

	if _, ok := perReqState.get("ip.reput_block_flag"); ok {
		t.Fatalf("Per request state key: ip.reput_block_flag should have been deleted")
	}

}

func TestSetvarActionExecuteExpandVars(t *testing.T) {
	param := "tx.anomaly_score=+%{tx.critical_anomaly_score}"
	sv, err := parseSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	perReqState := newEnvironment(&ScanResults{})
	perReqState.set("tx.anomaly_score", Value{IntToken(15)})
	perReqState.set("tx.critical_anomaly_score", Value{IntToken(5)})

	if err := executeSetVarAction(&sv, perReqState); err != nil {
		t.Fatalf("Unexpected error during execute %s", err)
	}

	val, ok := perReqState.get("tx.anomaly_score")
	if !ok {
		t.Fatalf("Per request state key: tx.anomaly_score not found")

	}

	if !val.equal(Value{IntToken(20)}) {
		t.Fatalf("Unexpected per request state key: tx.anomaly_score, value: %s", val)
	}
}
