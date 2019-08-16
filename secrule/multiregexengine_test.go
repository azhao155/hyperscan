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
						{"a%20bc", "/a%20bc.php", 1, 7, []byte("a%20bc")},
						{"a%20bc", "GET /a%20bc.php?arg1=something HTTP/1.1", 5, 11, []byte("a%20bc")},
						{"/p1/a%20bc.php", "/p1/a%20bc.php", 0, 14, []byte("/p1/a%20bc.php")},
						{"/", "/", 0, 1, []byte("/")},
						{"xyz", "xxyzz", 1, 4, []byte("xyz")},
						{"ab+c", "aaaaaaabccc;something=xxyzz", 0, 9, []byte("aaaaaaabc")},
						{"xyz", "aaaaaaabccc;something=xxyzz", 23, 26, []byte("xyz")},
						{"arg1", "arg1", 0, 5, []byte("arg1")},
						{"arg2", "arg2", 0, 5, []byte("arg2")},
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
