package secrule

import (
	"azwaf/waf"
	"bytes"
)

func newMockMultiRegexEngineFactory() waf.MultiRegexEngineFactory {
	return &mockMultiRegexEngineFactory{
		newMultiRegexEngineMockFunc: func(mm []waf.MultiRegexEnginePattern) waf.MultiRegexEngine {
			rxIds := make(map[string]int)
			for _, m := range mm {
				rxIds[m.Expr] = m.ID
			}

			return &mockMultiRegexEngine{
				scanMockFunc: func(input []byte) []waf.MultiRegexEngineMatch {
					type preCannedAnswer struct {
						rx   string
						val  string
						data []byte
					}
					preCannedAnswers := []preCannedAnswer{
						{"ab+c", "aaaaaaabccc", []byte("aaaaaaabc")},
						{"abc+", "aaaaaaabccc", []byte("abccc")},
						{"a+bc", "/hello.php?arg1=aaaaaaabccc", []byte("aaaaaaabc")},
						{"a%20bc", "/a%20bc.php", []byte("a%20bc")},
						{"a%20bc", "GET /a%20bc.php?arg1=something HTTP/1.1", []byte("a%20bc")},
						{"/p1/a%20bc.php", "/p1/a%20bc.php", []byte("/p1/a%20bc.php")},
						{"a%20bc.php", "a%20bc.php", []byte("a%20bc.php")},
						{"/", "/", []byte("/")},
						{"xyz", "xxyzz", []byte("xyz")},
						{"ab+c", "aaaaaaabccc;something=xxyzz", []byte("aaaaaaabc")},
						{"xyz", "aaaaaaabccc;something=xxyzz", []byte("xyz")},
						{"arg1", "arg1", []byte("arg1")},
						{"arg2", "arg2", []byte("arg2")},
						{"a%xxb", "a%xxb", []byte("a%xxb")},
						{"^$", "", []byte("")},
						{"^GET$", "GET", []byte("GET")},
						{"HTTP", "HTTP/1.1", []byte("HTTP")},
						{"^example\\.com$", "example.com", []byte("example.com")},
					}

					r := []waf.MultiRegexEngineMatch{}
					for _, a := range preCannedAnswers {
						if id, ok := rxIds[a.rx]; ok && bytes.Equal(input, []byte(a.val)) {
							r = append(r, waf.MultiRegexEngineMatch{ID: id, Data: a.data})
						}
					}

					return r
				},
			}
		},
	}
}

type mockMultiRegexEngine struct {
	scanMockFunc func(input []byte) []waf.MultiRegexEngineMatch
}

func (m *mockMultiRegexEngine) Scan(input []byte, scratchSpace waf.MultiRegexEngineScratchSpace) (matches []waf.MultiRegexEngineMatch, err error) {
	matches = m.scanMockFunc(input)
	return
}

func (m *mockMultiRegexEngine) CreateScratchSpace() (scratchSpace waf.MultiRegexEngineScratchSpace, err error) {
	return
}

func (m *mockMultiRegexEngine) Close() {
}

type mockMultiRegexEngineFactory struct {
	newMultiRegexEngineMockFunc func(mm []waf.MultiRegexEnginePattern) waf.MultiRegexEngine
}

func (mf *mockMultiRegexEngineFactory) NewMultiRegexEngine(mm []waf.MultiRegexEnginePattern) (m waf.MultiRegexEngine, err error) {
	m = mf.newMultiRegexEngineMockFunc(mm)
	return
}
