package hyperscan

import (
	pb "azwaf/proto"
	"azwaf/secrule"
	"testing"
)

func TestReqScannerSimpleRules(t *testing.T) {
	// Arrange
	mf := NewMultiRegexEngineFactory()
	rf := secrule.NewReqScannerFactory(mf)
	rules, _ := secrule.NewRuleParser().Parse(`
		SecRule ARGS "ab+c" "id:100"
		SecRule ARGS "abc+" "id:200,chain"
			SecRule ARGS "xyz" "t:lowercase"
		SecRule REQUEST_URI_RAW "a+bc" "id:300,t:lowercase,t:removewhitespace,x"
	`)
	req := &pb.WafHttpRequest{Uri: "/hello.php?arg1=ccaaaaaaabccc&arg2=helloworld"}

	// Act
	rs, err1 := rf.NewReqScanner(rules)
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
	if m.StartPos != 18 {
		t.Fatalf("Unexpected match pos: %d", m.StartPos)
	}
	if m.EndPos != 27 {
		t.Fatalf("Unexpected match pos: %d", m.EndPos)
	}

	m, ok = sr.GetRxResultsFor(200, 0, "ARGS")
	if !ok {
		t.Fatalf("Match not found")
	}
	if string(m.Data) != "abccc" {
		t.Fatalf("Unexpected match data: %s", string(m.Data))
	}
	if m.StartPos != 8 {
		t.Fatalf("Unexpected match StartPos: %d", m.StartPos)
	}
	if m.EndPos != 13 {
		t.Fatalf("Unexpected match EndPos: %d", m.EndPos)
	}

	m, ok = sr.GetRxResultsFor(200, 1, "ARGS")
	if ok {
		t.Fatalf("Unexpected match found")
	}
}
