package secrule

import "testing"

func TestNewSetvarActionDefaultAssignment(t *testing.T) {
	param := "ip.reput_block_flag"
	sv, err := newSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if sv.variable != "ip.reput_block_flag" {
		t.Fatalf("Got unexpected variable: %s", sv.variable)
	}

	if sv.operator != set {
		t.Fatalf("Got unexpected operator: %d", sv.operator)
	}

	if sv.value != "1" {
		t.Fatalf("Got unexpected value: %s", sv.value)
	}
}

func TestNewSetvarActionNumericAssignment(t *testing.T) {
	param := "ip.reput_block_flag=1"
	sv, err := newSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if sv.variable != "ip.reput_block_flag" {
		t.Fatalf("Got unexpected variable: %s", sv.variable)
	}

	if sv.operator != set {
		t.Fatalf("Got unexpected operator: %d", sv.operator)
	}

	if sv.value != "1" {
		t.Fatalf("Got unexpected value: %s", sv.value)
	}

	param = "tx.php_injection_score=+%{tx.critical_anomaly_score}"
	sv, err = newSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if sv.variable != "tx.php_injection_score" {
		t.Fatalf("Got unexpected variable: %s", sv.variable)
	}

	if sv.operator != increment {
		t.Fatalf("Got unexpected operator: %d", sv.operator)
	}

	if sv.value != "%{tx.critical_anomaly_score}" {
		t.Fatalf("Got unexpected value: %s", sv.value)
	}
}

func TestNewSetvarActionStringAssignment(t *testing.T) {
	param := "tx.sqli_select_statement=%{tx.sqli_select_statement} %{matched_var}"
	sv, err := newSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if sv.variable != "tx.sqli_select_statement" {
		t.Fatalf("Got unexpected variable: %s", sv.variable)
	}

	if sv.operator != set {
		t.Fatalf("Got unexpected operator: %d", sv.operator)
	}

	if sv.value != "%{tx.sqli_select_statement} %{matched_var}" {
		t.Fatalf("Got unexpected value: %s", sv.value)
	}
}

func TestNewSetvarActionDeletion(t *testing.T) {
	param := "!ip.reput_block_flag"
	sv, err := newSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if sv.variable != "ip.reput_block_flag" {
		t.Fatalf("Got unexpected variable: %s", sv.variable)
	}

	if sv.operator != deleteVar {
		t.Fatalf("Got unexpected operator: %d", sv.operator)
	}
}

func TestSetvarActionExecuteAssignment(t *testing.T) {
	param := "ip.reput_block_flag=1"
	sv, err := newSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	perReqState := newEnvMap()
	if ar := sv.execute(perReqState); ar.err != nil {
		t.Fatalf("Unexpected error during execute %s", ar.err)
	}

	val, ok := perReqState.get("ip.reput_block_flag")
	if !ok {
		t.Fatalf("Per request state key: ip.reput_block_flag not found")
	}

	if val.ToString() != "1" {
		t.Fatalf("Unexpected per request state key: ip.reput_block_flag, value: %s", val)
	}
}

func TestSetvarActionExecuteIncrement(t *testing.T) {
	param := "ip.reput_block_flag=+1"
	sv, err := newSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	perReqState := newEnvMap()
	perReqState.set("ip.reput_block_flag", &stringObject{Value: "1"})

	if ar := sv.execute(perReqState); ar.err != nil {
		t.Fatalf("Unexpected error during execute %s", ar.err)
	}

	val, ok := perReqState.get("ip.reput_block_flag")

	if !ok {
		t.Fatalf("Per request state key: ip.reput_block_flag not found")
	}

	if val.ToString() != "2" {
		t.Fatalf("Unexpected per request state key: ip.reput_block_flag, value: %s", val.ToString())
	}

	if _, ok := val.(*integerObject); !ok {
		t.Fatalf("Unexpected setting type")
	}
}

func TestSetvarActionExecuteDecrement(t *testing.T) {
	param := "ip.reput_block_flag=-1"
	sv, err := newSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	perReqState := newEnvMap()
	v := &stringObject{Value: "5"}
	perReqState.set("ip.reput_block_flag", v)

	if ar := sv.execute(perReqState); ar.err != nil {
		t.Fatalf("Unexpected error during execute %s", ar.err)
	}

	val, ok := perReqState.get("ip.reput_block_flag")
	if !ok {
		t.Fatalf("Per request state key: ip.reput_block_flag not found")
	}

	if val.ToString() != "4" {
		t.Fatalf("Unexpected per request state key: ip.reput_block_flag, value: %s", val.ToString())
	}

	if _, ok := val.(*integerObject); !ok {
		t.Fatalf("Unexpected setting type")
	}
}

func TestSetvarActionExecuteDelete(t *testing.T) {
	param := "!ip.reput_block_flag"
	sv, err := newSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	perReqState := newEnvMap()
	perReqState.set("ip.reput_block_flag", &stringObject{Value: "5"})

	if ar := sv.execute(perReqState); ar.err != nil {
		t.Fatalf("Unexpected error during execute %s", ar.err)
	}

	if _, ok := perReqState.get("ip.reput_block_flag"); ok {
		t.Fatalf("Per request state key: ip.reput_block_flag should have been deleted")
	}

}

func TestSetvarActionExecuteExpandVars(t *testing.T) {
	param := "tx.anomaly_score=+%{tx.critical_anomaly_score}"
	sv, err := newSetVarAction(param)
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	perReqState := newEnvMap()
	perReqState.set("tx.anomaly_score", &stringObject{Value: "15"})
	perReqState.set("tx.critical_anomaly_score", &stringObject{Value: "5"})

	if ar := sv.execute(perReqState); ar.err != nil {
		t.Fatalf("Unexpected error during execute %s", ar.err)
	}

	val, ok := perReqState.get("tx.anomaly_score")
	if !ok {
		t.Fatalf("Per request state key: tx.anomaly_score not found")

	}

	if val.ToString() != "20" {
		t.Fatalf("Unexpected per request state key: tx.anomaly_score, value: %s", val)
	}
}
