package ipreputation

import (
	"azwaf/waf"
	"errors"
	"io"
	"testing"
)

func TestEmptyList(t *testing.T) {
	engine := NewIPReputationEngine(&mockFileSystem{})
	engine.PutIPReputationList([]string{})
	request := &mockWafHTTPRequest{remoteAddr: "1.2.3.4"}

	isMatch := engine.EvalRequest(request)
	if isMatch {
		t.Fatalf("IPReputationEngine.EvalRequest false positive")
	}
}

func TestSingleIP(t *testing.T) {
	engine := NewIPReputationEngine(&mockFileSystem{})
	engine.PutIPReputationList([]string{"4.3.2.1"})

	request := &mockWafHTTPRequest{remoteAddr: "4.3.2.1"}
	isMatch := engine.EvalRequest(request)
	if !isMatch {
		t.Fatalf("IPReputationEngine.EvalRequest false negative")
	}

	request = &mockWafHTTPRequest{remoteAddr: "2.2.2.2"}
	isMatch = engine.EvalRequest(request)
	if isMatch {
		t.Fatalf("IPReputationEngine.EvalRequest false positive")
	}
}

func TestMultipleIPs(t *testing.T) {
	engine := NewIPReputationEngine(&mockFileSystem{})
	engine.PutIPReputationList([]string{"0.0.0.0", "255.255.255.255"})

	request := &mockWafHTTPRequest{remoteAddr: "0.0.0.0"}
	isMatch := engine.EvalRequest(request)
	if !isMatch {
		t.Fatalf("IPReputationEngine.EvalRequest false negative")
	}

	request = &mockWafHTTPRequest{remoteAddr: "255.255.255.255"}
	isMatch = engine.EvalRequest(request)
	if !isMatch {
		t.Fatalf("IPReputationEngine.EvalRequest false negative")
	}
}

func TestCIDR(t *testing.T) {
	engine := NewIPReputationEngine(&mockFileSystem{})
	engine.PutIPReputationList([]string{"127.0.0.0/8"})
	request := &mockWafHTTPRequest{remoteAddr: "127.12.7.0"}

	isMatch := engine.EvalRequest(request)
	if !isMatch {
		t.Fatalf("IPReputationEngine.EvalRequest false negative")
	}

	request = &mockWafHTTPRequest{remoteAddr: "128.12.7.0"}
	isMatch = engine.EvalRequest(request)
	if isMatch {
		t.Fatalf("IPReputationEngine.EvalRequest false positive")
	}
}

func TestNewIPReputationEngine(t *testing.T) {
	mockFs := &mockFileSystem{content: "0.0.0.0/32\n255.255.255.255"}
	engine := NewIPReputationEngine(mockFs)
	if mockFs.readFileCalled != 1 {
		t.Fatalf("NewIPReputationEngine didn't successfully read from disk")
	}

	request := &mockWafHTTPRequest{remoteAddr: "0.0.0.0"}
	isMatch := engine.EvalRequest(request)
	if !isMatch {
		t.Fatalf("NewIPReputationEngine didn't successfully parse IPs from disk")
	}

	request = &mockWafHTTPRequest{remoteAddr: "255.255.255.255"}
	isMatch = engine.EvalRequest(request)
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

func (m *mockFileSystem) writeFile(fileName string, data []byte) error {
	m.writeFileCalled++
	m.content = string(data)
	return nil
}

func (m *mockFileSystem) readFile(fileName string) (data []byte, err error) {
	m.readFileCalled++
	if m.content == "" {
		err = errors.New("")
	} else {
		data = []byte(m.content)
	}
	return
}

type mockWafHTTPRequest struct {
	remoteAddr string
}

func (r *mockWafHTTPRequest) Method() string                      { return "GET" }
func (r *mockWafHTTPRequest) URI() string                         { return "uri" }
func (r *mockWafHTTPRequest) ConfigID() string                    { return "configId" }
func (r *mockWafHTTPRequest) Headers() []waf.HeaderPair           { return nil }
func (r *mockWafHTTPRequest) BodyReader() io.Reader               { return nil }
func (r *mockWafHTTPRequest) LogMetaData() waf.RequestLogMetaData { return nil }
func (r *mockWafHTTPRequest) TransactionID() string               { return "abc" }
func (r *mockWafHTTPRequest) RemoteAddr() string                  { return r.remoteAddr }
