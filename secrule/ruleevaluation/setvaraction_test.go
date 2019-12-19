package ruleevaluation

import (
	. "azwaf/secrule/ast"

	"testing"
)

func TestSetvarActionExecuteAssignment(t *testing.T) {
	sv := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Set, Value: Value{IntToken(1)}}

	perReqState := NewEnvironment(nil)
	if err := executeSetVarAction(&sv, perReqState); err != nil {
		t.Fatalf("Unexpected error during execute %s", err)
	}

	val := perReqState.Get(EnvVarTx, "somevar")
	if val == nil {
		t.Fatalf("Per request state key: tx.somevar not found")
	}

	if !val.Equal(Value{IntToken(1)}) {
		t.Fatalf("Unexpected per request state key: tx.somevar, value: %s", val)
	}
}

func TestSetvarActionExecuteIncrement(t *testing.T) {
	sv := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Increment, Value: Value{IntToken(1)}}

	perReqState := NewEnvironment(nil)
	perReqState.Set(EnvVarTx, "somevar", Value{IntToken(1)})

	if err := executeSetVarAction(&sv, perReqState); err != nil {
		t.Fatalf("Unexpected error during execute %s", err)
	}

	val := perReqState.Get(EnvVarTx, "somevar")

	if val == nil {
		t.Fatalf("Per request state key: tx.somevar not found")
	}

	if !val.Equal(Value{IntToken(2)}) {
		t.Fatalf("Unexpected per request state key: tx.somevar, value: %s", val.String())
	}
}

func TestSetvarActionExecuteDecrement(t *testing.T) {
	sv := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: Decrement, Value: Value{IntToken(1)}}

	perReqState := NewEnvironment(nil)
	perReqState.Set(EnvVarTx, "somevar", Value{IntToken(5)})

	if err := executeSetVarAction(&sv, perReqState); err != nil {
		t.Fatalf("Unexpected error during execute %s", err)
	}

	val := perReqState.Get(EnvVarTx, "somevar")
	if val == nil {
		t.Fatalf("Per request state key: tx.somevar not found")
	}

	if !val.Equal(Value{IntToken(4)}) {
		t.Fatalf("Unexpected per request state key: tx.somevar, value: %s", val.String())
	}
}

func TestSetvarActionExecuteDelete(t *testing.T) {
	sv := SetVarAction{Variable: Value{StringToken("tx.somevar")}, Operator: DeleteVar}

	perReqState := NewEnvironment(nil)
	perReqState.Set(EnvVarTx, "somevar", Value{IntToken(5)})

	if err := executeSetVarAction(&sv, perReqState); err != nil {
		t.Fatalf("Unexpected error during execute %s", err)
	}

	if v := perReqState.Get(EnvVarTx, "somevar"); v != nil {
		t.Fatalf("Per request state key: tx.somevar should have been deleted")
	}
}

func TestSetvarActionExecuteExpandVars(t *testing.T) {
	sv := SetVarAction{Variable: Value{StringToken("tx.anomaly_score")}, Operator: Increment, Value: Value{MacroToken{Name: EnvVarTx, Selector: "critical_anomaly_score"}}}

	perReqState := NewEnvironment(nil)
	perReqState.Set(EnvVarTx, "anomaly_score", Value{IntToken(15)})
	perReqState.Set(EnvVarTx, "critical_anomaly_score", Value{IntToken(5)})

	if err := executeSetVarAction(&sv, perReqState); err != nil {
		t.Fatalf("Unexpected error during execute %s", err)
	}

	val := perReqState.Get(EnvVarTx, "anomaly_score")
	if val == nil {
		t.Fatalf("Per request state key: tx.anomaly_score not found")

	}

	if !val.Equal(Value{IntToken(20)}) {
		t.Fatalf("Unexpected per request state key: tx.anomaly_score, value: %s", val)
	}
}
