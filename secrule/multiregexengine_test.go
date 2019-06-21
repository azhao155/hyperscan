package secrule

import (
	"bytes"
)

func newMockMultiRegexEngineFactory() MultiRegexEngineFactory {
	return &mockMultiRegexEngineFactory{
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
