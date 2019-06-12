package hyperscan

import (
	pb "azwaf/proto"
	"azwaf/secrule"
	"testing"
)

func TestHyperscanAlone(t *testing.T) {
	// Arrange
	f := NewMultiRegexEngineFactory()
	e, err := f.NewMultiRegexEngine([]secrule.MultiRegexEnginePattern{
		{ID: 1, Expr: "ab+"},
		{ID: 2, Expr: "ac+"},
	})
	if err != nil {
		t.Fatalf("%s", err)
	}

	// Act
	m, err := e.Scan([]byte("abbbbcccccc"))

	// Assert
	if err != nil {
		t.Fatalf("%s", err)
	}
	if len(m) != 1 {
		t.Fatalf("Scan 1, unexpected count of matches: %d", len(m))
	}
	if m[0].ID != 1 {
		t.Fatalf("Scan 1, unexpected match ID: %d", m[0].ID)
	}
	if m[0].EndPos != 2 {
		t.Fatalf("Scan 1, unexpected match EndPos: %d", m[0].EndPos)
	}

	// Act
	m, err = e.Scan([]byte("accccccbbbb"))

	// Assert
	if err != nil {
		t.Fatalf("%s", err)
	}
	if len(m) != 1 {
		t.Fatalf("Scan 2, unexpected count of matches: %d", len(m))
	}
	if m[0].ID != 2 {
		t.Fatalf("Scan 2, unexpected match ID: %d", m[0].ID)
	}
	if m[0].EndPos != 2 {
		t.Fatalf("Scan 2, unexpected match EndPos: %d", m[0].EndPos)
	}

}

func TestReqScannerSimpleRules(t *testing.T) {
	// Arrange
	f := NewMultiRegexEngineFactory()
	rules := []secrule.Rule{
		{
			ID: 100,
			Items: []secrule.RuleItem{
				{
					Targets:         []string{"ARGS"},
					Op:              secrule.Rx,
					Val:             "ab+c",
					Transformations: []secrule.Transformation{},
				},
			},
		},
		{
			ID: 200,
			Items: []secrule.RuleItem{
				{
					Targets:         []string{"ARGS"},
					Op:              secrule.Rx,
					Val:             "abc+",
					Transformations: []secrule.Transformation{},
				},
				{
					Targets:         []string{"ARGS"},
					Op:              secrule.Rx,
					Val:             "xyz",
					Transformations: []secrule.Transformation{secrule.Lowercase},
				},
			},
		},
		{
			ID: 300,
			Items: []secrule.RuleItem{
				{
					Targets:         []string{"REQUEST_URI_RAW"},
					Op:              secrule.Rx,
					Val:             "a+bc",
					Transformations: []secrule.Transformation{secrule.Lowercase, secrule.RemoveWhitespace},
				},
			},
		},
	}
	req := &pb.WafHttpRequest{
		Uri: "/hello.php?arg1=aaaaaaabccc&arg2=helloworld",
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
	if m.EndPos != 25 {
		t.Fatalf("Unexpected match pos: %d", m.EndPos)
	}

	m, ok = sr.GetRxResultsFor(200, 0, "ARGS")
	if !ok {
		t.Fatalf("Match not found")
	}
	if m.EndPos != 9 {
		t.Fatalf("Unexpected match pos: %d", m.EndPos)
	}

	m, ok = sr.GetRxResultsFor(200, 1, "ARGS")
	if ok {
		t.Fatalf("Unexpected match found")
	}
}
