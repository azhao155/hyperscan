package secrule

import "testing"

func TestEnvironmentSet(t *testing.T) {
	m := newEnvironment(&ScanResults{})
	v := &stringObject{Value: "v"}
	m.set("k", v)
	// Same case
	if v, ok := m.get("k"); !ok {
		t.Fatalf("Key k not found in map")
	} else if v != v {
		t.Fatalf("Unexpected value for key k")
	}

	// Different case
	v.Value = "V"
	m.set("K", v)
	if v, ok := m.get("K"); !ok {
		t.Fatalf("Key K not found in map")
	} else if v != v {
		t.Fatalf("Unexpected value for key k")
	}
}

func TestEnvironmentGet(t *testing.T) {
	m := newEnvironment(&ScanResults{})
	v := &stringObject{Value: "v"}
	m.set("k", v)

	// Same case
	if v, ok := m.get("k"); !ok {
		t.Fatalf("Key k not found in map")
	} else if v != v {
		t.Fatalf("Unexpected value for key k")
	}

	// Different case
	if v, ok := m.get("K"); !ok {
		t.Fatalf("Key K not found in map")
	} else if v != v {
		t.Fatalf("Unexpected value for key k")
	}
}

func TestEnvironmentHasKey(t *testing.T) {
	m := newEnvironment(&ScanResults{})
	v := &stringObject{Value: "v"}
	m.set("k", v)

	if ok := m.hasKey("k"); !ok {
		t.Fatalf("Key k not found in map")
	}

	if ok := m.hasKey("K"); !ok {
		t.Fatalf("Key K not found in map")
	}
}
