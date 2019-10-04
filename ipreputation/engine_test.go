package ipreputation

import (
	"azwaf/waf"
	"errors"
	"testing"
)

func TestEmptyList(t *testing.T) {
	engine := NewIPReputationEngine(&mockFileSystem{})
	engine.PutIPReputationList([]string{})
	request := &mockHTTPRequest{remoteAddr: "1.2.3.4"}

	isMatch := engine.EvalRequest(request) == waf.Block
	if isMatch {
		t.Fatalf("IPReputationEngine.EvalRequest false positive")
	}
}

func TestSingleIP(t *testing.T) {
	engine := NewIPReputationEngine(&mockFileSystem{})
	engine.PutIPReputationList([]string{"4.3.2.1"})

	request := &mockHTTPRequest{remoteAddr: "4.3.2.1"}
	isMatch := engine.EvalRequest(request) == waf.Block
	if !isMatch {
		t.Fatalf("IPReputationEngine.EvalRequest false negative")
	}

	request = &mockHTTPRequest{remoteAddr: "2.2.2.2"}
	isMatch = engine.EvalRequest(request) == waf.Block
	if isMatch {
		t.Fatalf("IPReputationEngine.EvalRequest false positive")
	}
}

func TestMultipleIPs(t *testing.T) {
	engine := NewIPReputationEngine(&mockFileSystem{})
	engine.PutIPReputationList([]string{"0.0.0.0", "255.255.255.255"})

	request := &mockHTTPRequest{remoteAddr: "0.0.0.0"}
	isMatch := engine.EvalRequest(request) == waf.Block
	if !isMatch {
		t.Fatalf("IPReputationEngine.EvalRequest false negative")
	}

	request = &mockHTTPRequest{remoteAddr: "255.255.255.255"}
	isMatch = engine.EvalRequest(request) == waf.Block
	if !isMatch {
		t.Fatalf("IPReputationEngine.EvalRequest false negative")
	}
}

func TestCIDR(t *testing.T) {
	engine := NewIPReputationEngine(&mockFileSystem{})
	engine.PutIPReputationList([]string{"127.0.0.0/8"})
	request := &mockHTTPRequest{remoteAddr: "127.12.7.0"}

	isMatch := engine.EvalRequest(request) == waf.Block
	if !isMatch {
		t.Fatalf("IPReputationEngine.EvalRequest false negative")
	}

	request = &mockHTTPRequest{remoteAddr: "128.12.7.0"}
	isMatch = engine.EvalRequest(request) == waf.Block
	if isMatch {
		t.Fatalf("IPReputationEngine.EvalRequest false positive")
	}
}

func TestXForwardedForHeaders(t *testing.T) {
	engine := NewIPReputationEngine(&mockFileSystem{})
	engine.PutIPReputationList([]string{"127.0.0.0/8"})
	request := &mockHTTPRequest{
		remoteAddr: "0.0.0.0",
		headers:    []waf.HeaderPair{&mockHeaderPair{key: "X-Forwarded-For", value: "127.0.0.0:3000"}},
	}

	isMatch := engine.EvalRequest(request) == waf.Block
	if !isMatch {
		t.Fatalf("IPReputationEngine.EvalRequest false negative")
	}

	request = &mockHTTPRequest{remoteAddr: "128.12.7.0"}
	isMatch = engine.EvalRequest(request) == waf.Block
	if isMatch {
		t.Fatalf("IPReputationEngine.EvalRequest false positive")
	}
}

func TestXForwardedForHeadersWithoutPort(t *testing.T) {
	engine := NewIPReputationEngine(&mockFileSystem{})
	engine.PutIPReputationList([]string{"127.0.0.0/8"})
	request := &mockHTTPRequest{
		remoteAddr: "0.0.0.0",
		headers:    []waf.HeaderPair{&mockHeaderPair{key: "X-Forwarded-For", value: "127.0.0.0"}},
	}

	isMatch := engine.EvalRequest(request) == waf.Block
	if !isMatch {
		t.Fatalf("IPReputationEngine.EvalRequest false negative")
	}
}

func TestXForwardedForHeadersWithWhiteSpace(t *testing.T) {
	engine := NewIPReputationEngine(&mockFileSystem{})
	engine.PutIPReputationList([]string{"127.0.0.0/8"})
	request := &mockHTTPRequest{
		remoteAddr: "0.0.0.0",
		headers:    []waf.HeaderPair{&mockHeaderPair{key: "X-Forwarded-For", value: " 1.2.3.4:80 , 127.0.0.0:3000 "}},
	}

	isMatch := engine.EvalRequest(request) == waf.Block
	if !isMatch {
		t.Fatalf("IPReputationEngine.EvalRequest false negative")
	}
}

func TestNewIPReputationEngine(t *testing.T) {
	mockFs := &mockFileSystem{content: "0.0.0.0/32\n255.255.255.255"}
	engine := NewIPReputationEngine(mockFs)
	if mockFs.readFileCalled != 1 {
		t.Fatalf("NewIPReputationEngine didn't successfully read from disk")
	}

	request := &mockHTTPRequest{remoteAddr: "0.0.0.0"}
	isMatch := engine.EvalRequest(request) == waf.Block
	if !isMatch {
		t.Fatalf("NewIPReputationEngine didn't successfully parse IPs from disk")
	}

	request = &mockHTTPRequest{remoteAddr: "255.255.255.255"}
	isMatch = engine.EvalRequest(request) == waf.Block
	if !isMatch {
		t.Fatalf("NewIPReputationEngine didn't successfully parse IPs from disk")
	}
}

func TestPutIPReputationList(t *testing.T) {
	mockFs := &mockFileSystem{}
	engine := NewIPReputationEngine(mockFs)

	engine.PutIPReputationList([]string{"0.0.0.0", "255.255.255.255/32"})
	if mockFs.writeFileCalled != 1 {
		t.Fatalf("IPReputationEngine.PutIPReputationList didn't successfully write to disk")
	}
}

type mockFileSystem struct {
	writeFileCalled int
	readFileCalled  int
	content         string
}

func (m *mockFileSystem) WriteFile(fileName string, data []byte) error {
	m.writeFileCalled++
	m.content = string(data)
	return nil
}

func (m *mockFileSystem) ReadFile(fileName string) (data []byte, err error) {
	m.readFileCalled++
	if m.content == "" {
		err = errors.New("")
	} else {
		data = []byte(m.content)
	}
	return
}

type mockHTTPRequest struct {
	remoteAddr string
	headers    []waf.HeaderPair
}

func (r *mockHTTPRequest) RemoteAddr() string        { return r.remoteAddr }
func (r *mockHTTPRequest) Headers() []waf.HeaderPair { return r.headers }

type mockHeaderPair struct {
	key   string
	value string
}

func (h *mockHeaderPair) Key() string   { return h.key }
func (h *mockHeaderPair) Value() string { return h.value }
