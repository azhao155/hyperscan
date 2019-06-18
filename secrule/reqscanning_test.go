package secrule

import (
	pb "azwaf/proto"
	"bytes"
	"testing"
)

func TestReqScanner1(t *testing.T) {
	// Arrange
	mf := &mockMultiRegexEngineFactory{
		newMultiRegexEngineMockFunc: func(mm []MultiRegexEnginePattern) MultiRegexEngine {
			rxIds := make(map[string]int)
			for _, m := range mm {
				rxIds[m.Expr] = m.ID
			}

			return &mockMultiRegexEngine{
				scanMockFunc: func(input []byte) []MultiRegexEngineMatch {
					type preCannedAnswer struct {
						rx       string
						val      string
						startPos int
						endPos   int
						data     []byte
					}
					preCannedAnswers := []preCannedAnswer{
						{"ab+c", "aaaaaaabccc", 0, 9, []byte("aaaaaaabc")},
						{"abc+", "aaaaaaabccc", 6, 11, []byte("abccc")},
						{"a+bc", "/hello.php?arg1=aaaaaaabccc", 16, 25, []byte("aaaaaaabc")},
					}

					r := []MultiRegexEngineMatch{}
					for _, a := range preCannedAnswers {
						if id, ok := rxIds[a.rx]; ok && bytes.Equal(input, []byte(a.val)) {
							r = append(r, MultiRegexEngineMatch{ID: id, StartPos: a.startPos, EndPos: a.endPos, Data: a.data})
						}
					}

					return r
				},
			}
		},
	}
	rules := []Rule{
		{
			ID: 100,
			Items: []RuleItem{
				{Targets: []string{"ARGS"}, Op: Rx, Val: "ab+c", Transformations: []Transformation{}},
			},
		},
		{
			ID: 200,
			Items: []RuleItem{
				{Targets: []string{"ARGS"}, Op: Rx, Val: "abc+", Transformations: []Transformation{}},
				{Targets: []string{"ARGS"}, Op: Rx, Val: "xyz", Transformations: []Transformation{Lowercase}},
			},
		},
		{
			ID: 300,
			Items: []RuleItem{
				{Targets: []string{"REQUEST_URI_RAW"}, Op: Rx, Val: "a+bc", Transformations: []Transformation{Lowercase, RemoveWhitespace}},
			},
		},
	}
	req := &pb.WafHttpRequest{
		Uri: "/hello.php?arg1=aaaaaaabccc",
	}

	// Act
	rs, err1 := NewReqScanner(rules, mf)
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

type mockMultiRegexEngine struct {
	scanMockFunc func(input []byte) []MultiRegexEngineMatch
}

func (m *mockMultiRegexEngine) Scan(input []byte) (matches []MultiRegexEngineMatch, err error) {
	matches = m.scanMockFunc(input)
	return
}

func (m *mockMultiRegexEngine) Close() {
}

type mockMultiRegexEngineFactory struct {
	newMultiRegexEngineMockFunc func(mm []MultiRegexEnginePattern) MultiRegexEngine
}

func (mf *mockMultiRegexEngineFactory) NewMultiRegexEngine(mm []MultiRegexEnginePattern) (m MultiRegexEngine, err error) {
	m = mf.newMultiRegexEngineMockFunc(mm)
	return
}
