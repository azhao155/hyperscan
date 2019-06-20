package hyperscan

import (
	pb "azwaf/proto"
	"azwaf/secrule"
	"testing"
)

func TestReqScannerSimpleRules(t *testing.T) {
	// Arrange
	f := NewMultiRegexEngineFactory()
	rules := []secrule.Rule{
		{
			ID: 100,
			Items: []secrule.RuleItem{
				{
					Predicate:       secrule.RulePredicate{Targets: []string{"ARGS"}, Op: secrule.Rx, Val: "ab+c"},
					Transformations: []secrule.Transformation{},
				},
			},
		},
		{
			ID: 200,
			Items: []secrule.RuleItem{
				{
					Predicate:       secrule.RulePredicate{Targets: []string{"ARGS"}, Op: secrule.Rx, Val: "abc+"},
					Transformations: []secrule.Transformation{},
				},
				{
					Predicate:       secrule.RulePredicate{Targets: []string{"ARGS"}, Op: secrule.Rx, Val: "xyz"},
					Transformations: []secrule.Transformation{secrule.Lowercase},
				},
			},
		},
		{
			ID: 300,
			Items: []secrule.RuleItem{
				{
					Predicate:       secrule.RulePredicate{Targets: []string{"REQUEST_URI_RAW"}, Op: secrule.Rx, Val: "a+bc"},
					Transformations: []secrule.Transformation{secrule.Lowercase, secrule.RemoveWhitespace},
				},
			},
		},
	}
	req := &pb.WafHttpRequest{
		Uri: "/hello.php?arg1=ccaaaaaaabccc&arg2=helloworld",
	}

	// Act
	rs, err1 := secrule.NewReqScanner(rules, f)
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
