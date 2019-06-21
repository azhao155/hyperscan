package secrule

import (
	pb "azwaf/proto"
	"testing"
)

func TestReqScanner1(t *testing.T) {
	// Arrange
	mf := newMockMultiRegexEngineFactory()
	rsf := NewReqScannerFactory(mf)
	rules, _ := newMockRuleLoader().Rules("some ruleset")
	req := &pb.WafHttpRequest{Uri: "/hello.php?arg1=aaaaaaabccc"}

	// Act
	rs, err1 := rsf.NewReqScanner(rules)
	sr, err2 := rs.Scan(req)

	// Assert
	if err1 != nil {
		t.Fatalf("Got unexpected error: %s", err1)
	}
	if err2 != nil {
		t.Fatalf("Got unexpected error: %s", err2)
	}

	m, ok := sr.GetRxResultsFor(300, 0, "REQUEST_URI_RAW")
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "aaaaaaabc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
	if m.StartPos != 16 {
		t.Fatalf("Unexpected match pos: %d", m.StartPos)
	}
	if m.EndPos != 25 {
		t.Fatalf("Unexpected match pos: %d", m.EndPos)
	}

	m, ok = sr.GetRxResultsFor(200, 0, "ARGS")
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "abccc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
	if m.StartPos != 6 {
		t.Fatalf("Unexpected match pos: %d", m.StartPos)
	}
	if m.EndPos != 11 {
		t.Fatalf("Unexpected match pos: %d", m.EndPos)
	}

	m, ok = sr.GetRxResultsFor(200, 1, "ARGS")
	if ok {
		t.Fatalf("Unexpected match found")
	}
}
