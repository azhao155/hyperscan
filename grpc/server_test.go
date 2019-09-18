package grpc

import (
	pb "azwaf/proto"
	"azwaf/waf"
	"bytes"
	"io"
	"strings"
	"testing"

	"google.golang.org/grpc"
)

func TestGrpcServerEvalRequestSimple(t *testing.T) {
	// Arrange
	mw := &mockWafServer{}
	s := &serverImpl{ws: mw}
	stream := &mockWafServiceEvalRequestServer{
		messages: []*pb.WafHttpRequest{
			&pb.WafHttpRequest{
				Content: &pb.WafHttpRequest_HeadersAndFirstChunk{
					HeadersAndFirstChunk: &pb.HeadersAndFirstChunk{
						Uri: "/helloworld",
						Headers: []*pb.HeaderPair{
							{Key: "Host", Value: "example.com"},
							{Key: "User-Agent", Value: "curl/7.50.3"},
							{Key: "Accept", Value: "*/*"},
						},
					},
				},
			},
		},
	}

	// Act
	err := s.EvalRequest(stream)

	// Assert
	if err != nil {
		t.Fatalf("Unexpected error: %v.", err)
	}

	if mw.receivedBodyErr != nil {
		t.Fatalf("Unexpected receivedBodyErr: %v.", mw.receivedBodyErr)
	}

	if mw.evalRequestCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockWafServer.EvalRequest. Expected: 1. Actual: %v.", mw.evalRequestCalled)
	}

	if mw.receivedBody.Len() != 0 {
		t.Fatalf("Unexpected body received.")
	}
}

func TestGrpcServerEvalRequestBodyInFirstMsg(t *testing.T) {
	// Arrange
	mw := &mockWafServer{}
	s := &serverImpl{ws: mw}
	stream := &mockWafServiceEvalRequestServer{
		messages: []*pb.WafHttpRequest{
			&pb.WafHttpRequest{
				Content: &pb.WafHttpRequest_HeadersAndFirstChunk{
					HeadersAndFirstChunk: &pb.HeadersAndFirstChunk{
						Uri: "/helloworld",
						Headers: []*pb.HeaderPair{
							{Key: "Host", Value: "example.com"},
							{Key: "User-Agent", Value: "curl/7.50.3"},
							{Key: "Accept", Value: "*/*"},
						},
						FirstBodyChunk: []byte("hello world body"),
					},
				},
			},
		},
	}

	// Act
	err := s.EvalRequest(stream)

	// Assert
	if err != nil {
		t.Fatalf("Unexpected error: %v.", err)
	}

	if mw.receivedBodyErr != nil {
		t.Fatalf("Unexpected receivedBodyErr: %v.", mw.receivedBodyErr)
	}

	if mw.evalRequestCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockWafServer.EvalRequest. Expected: 1. Actual: %v.", mw.evalRequestCalled)
	}

	expected := "hello world body"
	if mw.receivedBody.String() != expected {
		t.Fatalf("Unexpected body received. Expected: %v. Actual: %v.", expected, mw.receivedBody.String())
	}
}

func TestGrpcServerEvalRequestStreamingBody(t *testing.T) {
	// Arrange
	mw := &mockWafServer{}
	s := &serverImpl{ws: mw}
	stream := &mockWafServiceEvalRequestServer{
		messages: []*pb.WafHttpRequest{
			&pb.WafHttpRequest{
				Content: &pb.WafHttpRequest_HeadersAndFirstChunk{
					HeadersAndFirstChunk: &pb.HeadersAndFirstChunk{
						Uri: "/helloworld",
						Headers: []*pb.HeaderPair{
							{Key: "Host", Value: "example.com"},
							{Key: "User-Agent", Value: "curl/7.50.3"},
							{Key: "Accept", Value: "*/*"},
						},
						FirstBodyChunk: []byte("hello world body, "),
						MoreBodyChunks: true,
					},
				},
			},
			&pb.WafHttpRequest{
				Content: &pb.WafHttpRequest_NextBodyChunk{
					NextBodyChunk: &pb.NextBodyChunk{
						BodyChunk:      []byte("next chunk"),
						MoreBodyChunks: false,
					},
				},
			},
		},
	}

	// Act
	err := s.EvalRequest(stream)

	// Assert
	if err != nil {
		t.Fatalf("Unexpected error: %v.", err)
	}

	if mw.receivedBodyErr != nil {
		t.Fatalf("Unexpected receivedBodyErr: %v.", mw.receivedBodyErr)
	}

	if mw.evalRequestCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockWafServer.EvalRequest. Expected: 1. Actual: %v.", mw.evalRequestCalled)
	}

	expected := "hello world body, next chunk"
	if mw.receivedBody.String() != expected {
		t.Fatalf("Unexpected body received. Expected: %v. Actual: %v.", expected, mw.receivedBody.String())
	}
}

func TestGrpcServerEvalRequestStreamingBodyManyChunks(t *testing.T) {
	// Arrange
	mw := &mockWafServer{}
	s := &serverImpl{ws: mw}
	stream := &mockWafServiceEvalRequestServer{
		messages: []*pb.WafHttpRequest{
			&pb.WafHttpRequest{
				Content: &pb.WafHttpRequest_HeadersAndFirstChunk{
					HeadersAndFirstChunk: &pb.HeadersAndFirstChunk{
						Uri:            "/helloworld",
						FirstBodyChunk: []byte("hello "),
						MoreBodyChunks: true,
					},
				},
			},
		},
	}

	for i := 0; i < 20; i++ {
		stream.messages = append(stream.messages, &pb.WafHttpRequest{
			Content: &pb.WafHttpRequest_NextBodyChunk{
				NextBodyChunk: &pb.NextBodyChunk{
					BodyChunk:      []byte("hello "),
					MoreBodyChunks: true,
				},
			},
		})
	}

	stream.messages = append(stream.messages, &pb.WafHttpRequest{
		Content: &pb.WafHttpRequest_NextBodyChunk{
			NextBodyChunk: &pb.NextBodyChunk{
				BodyChunk:      []byte("hello "),
				MoreBodyChunks: false,
			},
		},
	})

	// Act
	err := s.EvalRequest(stream)

	// Assert
	if err != nil {
		t.Fatalf("Unexpected error: %v.", err)
	}

	if mw.receivedBodyErr != nil {
		t.Fatalf("Unexpected receivedBodyErr: %v.", mw.receivedBodyErr)
	}

	if mw.evalRequestCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockWafServer.EvalRequest. Expected: 1. Actual: %v.", mw.evalRequestCalled)
	}

	expected := strings.Repeat("hello ", 22)
	if mw.receivedBody.String() != expected {
		t.Fatalf("Unexpected body received. Expected: %v. Actual: %v.", expected, mw.receivedBody.String())
	}
}

func TestGrpcServerEvalRequestStreamingBodyLyingLastChunk(t *testing.T) {
	// Arrange
	mw := &mockWafServer{}
	s := &serverImpl{ws: mw}
	stream := &mockWafServiceEvalRequestServer{
		messages: []*pb.WafHttpRequest{
			&pb.WafHttpRequest{
				Content: &pb.WafHttpRequest_HeadersAndFirstChunk{
					HeadersAndFirstChunk: &pb.HeadersAndFirstChunk{
						Uri:            "/helloworld",
						FirstBodyChunk: []byte("hello "),
						MoreBodyChunks: true,
					},
				},
			},
			&pb.WafHttpRequest{
				Content: &pb.WafHttpRequest_NextBodyChunk{
					NextBodyChunk: &pb.NextBodyChunk{
						BodyChunk:      []byte("hello "),
						MoreBodyChunks: true, // Note: the last chunk should actually say false here, but this tests ensure robustness to violating this
					},
				},
			},
		},
	}

	// Act
	err := s.EvalRequest(stream)

	// Assert
	if err != nil {
		t.Fatalf("Unexpected error: %v.", err)
	}

	if mw.receivedBodyErr != nil {
		t.Fatalf("Unexpected receivedBodyErr: %v.", mw.receivedBodyErr)
	}

	if mw.evalRequestCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockWafServer.EvalRequest. Expected: 1. Actual: %v.", mw.evalRequestCalled)
	}

	expected := "hello hello "
	if mw.receivedBody.String() != expected {
		t.Fatalf("Unexpected body received. Expected: %v. Actual: %v.", expected, mw.receivedBody.String())
	}
}

func TestGrpcServerEvalRequestStreamingBodySmallBuffer(t *testing.T) {
	// Arrange

	mw := &mockWafServer{
		bodyReadBufSize: 10,
	}
	s := &serverImpl{ws: mw}
	stream := &mockWafServiceEvalRequestServer{
		messages: []*pb.WafHttpRequest{
			&pb.WafHttpRequest{
				Content: &pb.WafHttpRequest_HeadersAndFirstChunk{
					HeadersAndFirstChunk: &pb.HeadersAndFirstChunk{
						Uri:            "/helloworld",
						FirstBodyChunk: make([]byte, 1000),
						MoreBodyChunks: true,
					},
				},
			},
			&pb.WafHttpRequest{
				Content: &pb.WafHttpRequest_NextBodyChunk{
					NextBodyChunk: &pb.NextBodyChunk{
						BodyChunk:      make([]byte, 1000),
						MoreBodyChunks: false,
					},
				},
			},
		},
	}

	// Act
	err := s.EvalRequest(stream)

	// Assert
	if err != nil {
		t.Fatalf("Unexpected error: %v.", err)
	}

	if mw.receivedBodyErr != nil {
		t.Fatalf("Unexpected receivedBodyErr: %v.", mw.receivedBodyErr)
	}

	if mw.evalRequestCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockWafServer.EvalRequest. Expected: 1. Actual: %v.", mw.evalRequestCalled)
	}

	expected := make([]byte, 2000)
	if !bytes.Equal([]byte(mw.receivedBody.String()), expected) {
		t.Fatalf("Unexpected body received.")
	}
}

func TestGrpcServerEvalRequestStreamingProtocolViolation1(t *testing.T) {
	// Arrange

	mw := &mockWafServer{
		bodyReadBufSize: 10,
	}
	s := &serverImpl{ws: mw}
	stream := &mockWafServiceEvalRequestServer{
		messages: []*pb.WafHttpRequest{
			&pb.WafHttpRequest{
				Content: &pb.WafHttpRequest_HeadersAndFirstChunk{
					HeadersAndFirstChunk: &pb.HeadersAndFirstChunk{
						Uri:            "/helloworld",
						FirstBodyChunk: []byte("hello world"),
						MoreBodyChunks: true,
					},
				},
			},
			&pb.WafHttpRequest{
				Content: &pb.WafHttpRequest_HeadersAndFirstChunk{
					HeadersAndFirstChunk: &pb.HeadersAndFirstChunk{
						Uri:            "/helloworld",
						FirstBodyChunk: []byte("hello world"),
						MoreBodyChunks: false,
					},
				},
			},
		},
	}

	// Act
	err := s.EvalRequest(stream)

	// Assert
	if err != nil {
		t.Fatalf("Unexpected error: %v.", err)
	}

	expected := "subsequent gRPC message was not NextBodyChunk"
	if mw.receivedBodyErr == nil || mw.receivedBodyErr.Error() != expected {
		t.Fatalf("Unexpected error received while reading body. Expected: %v. Actual: %v.", expected, mw.receivedBodyErr)
	}
}

func TestGrpcServerEvalRequestStreamingProtocolViolation2(t *testing.T) {
	// Arrange

	mw := &mockWafServer{
		bodyReadBufSize: 10,
	}
	s := &serverImpl{ws: mw}
	stream := &mockWafServiceEvalRequestServer{
		messages: []*pb.WafHttpRequest{
			&pb.WafHttpRequest{
				Content: &pb.WafHttpRequest_NextBodyChunk{
					NextBodyChunk: &pb.NextBodyChunk{
						BodyChunk:      []byte("hello world"),
						MoreBodyChunks: true,
					},
				},
			},
			&pb.WafHttpRequest{
				Content: &pb.WafHttpRequest_HeadersAndFirstChunk{
					HeadersAndFirstChunk: &pb.HeadersAndFirstChunk{
						Uri:            "/helloworld",
						FirstBodyChunk: []byte("hello world"),
						MoreBodyChunks: false,
					},
				},
			},
		},
	}

	// Act
	err := s.EvalRequest(stream)

	// Assert
	expected := "first gRPC stream message was not HeadersAndFirstChunk"
	if err == nil || err.Error() != expected {
		t.Fatalf("Unexpected error. Expected: %v. Actual: %v.", expected, mw.receivedBodyErr)
	}
}

func TestGrpcServerPutIPReputationListEmpty(t *testing.T) {
	mw := &mockWafServer{
		bodyReadBufSize: 10,
	}
	s := &serverImpl{ws: mw}
	stream := &mockWafServicePutIPReputationListServer{}

	s.PutIPReputationList(stream)
	if mw.putIPReputationListCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockWafServer.PutIPReputationList")
	}
}

func TestGrpcServerPutIPReputationListWithData(t *testing.T) {
	mw := &mockWafServer{
		bodyReadBufSize: 10,
	}
	s := &serverImpl{ws: mw}
	stream := &mockWafServicePutIPReputationListServer{ips: [][]string{[]string{"0.0.0.0/32", "255.255.255.255"}, []string{"122.122.122.122/12", "10.20.30.40"}}}

	s.PutIPReputationList(stream)
	if mw.putIPReputationListCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockWafServer.PutIPReputationList")
	}
}

func TestGrpcServerPutConfig(t *testing.T) {
	// Arrange
	mw := &mockWafServer{}
	s := &serverImpl{ws: mw}
	config := &pb.WAFConfig{}

	// Act
	s.PutConfig(nil, config)

	// Assert
	if mw.putConfigCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockWafServer.PutConfig")
	}
}

func TestGrpcServerDisposeConfig(t *testing.T) {
	// Arrange
	mw := &mockWafServer{}
	s := &serverImpl{ws: mw}
	version := &pb.WAFConfigVersion{}

	// Act
	s.DisposeConfig(nil, version)

	// Assert
	if mw.disposeConfigCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockWafServer.DisposeConfig")
	}
}

func TestGrpcServerPutGeoIPData(t *testing.T) {
	// Arrange
	mw := &mockWafServer{}
	s := &serverImpl{ws: mw}
	stream := &mockWafServicePutGeoIPDataServer{
		messages: []*pb.GeoIPData{
			&pb.GeoIPData{
				GeoIPDataRecords: []*pb.GeoIPDataRecord{
					&pb.GeoIPDataRecord{StartIP: 34064466, EndIP: 34064483, CountryCode: "FR"},
					&pb.GeoIPDataRecord{StartIP: 412372463, EndIP: 412372463, CountryCode: "FR"},
				},
			},
			&pb.GeoIPData{
				GeoIPDataRecords: []*pb.GeoIPDataRecord{
					&pb.GeoIPDataRecord{StartIP: 412372463, EndIP: 412372463, CountryCode: "FR"},
					&pb.GeoIPDataRecord{StartIP: 416447260, EndIP: 416447260, CountryCode: "US"},
				},
			},
		},
	}

	// Act
	err := s.PutGeoIPData(stream)

	// Assert
	if err != nil {
		t.Fatalf("Unexpected error: %v.", err)
	}

	if mw.putGeoIPDataCalled != 1 {
		t.Fatalf("Unexpected number of calls to mockWafServer.PutGeoIPData. Expected: 1. Actual: %v.", mw.evalRequestCalled)
	}
}

type mockWafServer struct {
	evalRequestCalled         int
	putConfigCalled           int
	putGeoIPDataCalled        int
	putIPReputationListCalled int
	disposeConfigCalled       int
	receivedBody              strings.Builder
	receivedBodyErr           error
	bodyReadBufSize           int
}

func (m *mockWafServer) EvalRequest(req waf.HTTPRequest) (decision waf.Decision, err error) {
	m.evalRequestCalled++

	if m.bodyReadBufSize == 0 {
		m.bodyReadBufSize = 10000
	}
	bb := make([]byte, m.bodyReadBufSize)
	for {
		n, bodyErr := req.BodyReader().Read(bb)
		m.receivedBody.Write(bb[:n])
		if bodyErr == io.EOF {
			break
		}
		if bodyErr != nil {
			m.receivedBodyErr = bodyErr
			return
		}
	}

	decision = waf.Pass
	return
}

type mockWafServiceEvalRequestServer struct {
	grpc.ServerStream
	messages []*pb.WafHttpRequest
}

func (m *mockWafServiceEvalRequestServer) Recv() (req *pb.WafHttpRequest, err error) {
	if len(m.messages) == 0 {
		err = io.EOF
		return
	}

	req = m.messages[0]
	m.messages = m.messages[1:]
	return
}

func (m *mockWafServiceEvalRequestServer) SendAndClose(*pb.WafDecision) error {
	return nil
}

type mockWafServicePutIPReputationListServer struct {
	grpc.ServerStream
	ips   [][]string
	index int
}

func (m *mockWafServicePutIPReputationListServer) Recv() (list *pb.IpReputationList, err error) {
	if m.index < len(m.ips) {
		list = &pb.IpReputationList{Ip: m.ips[m.index]}
		m.index++
	} else {
		err = io.EOF
	}
	return
}

func (m *mockWafServicePutIPReputationListServer) SendAndClose(*pb.PutIPReputationListResponse) error {
	return nil
}

func (m *mockWafServer) PutConfig(c waf.Config) error {
	m.putConfigCalled++
	return nil
}

func (m *mockWafServer) PutGeoIPData(data []waf.GeoIPDataRecord) error {
	m.putGeoIPDataCalled++
	return nil
}

func (m *mockWafServer) DisposeConfig(v int) error {
	m.disposeConfigCalled++
	return nil
}

type mockWafServicePutGeoIPDataServer struct {
	grpc.ServerStream
	messages []*pb.GeoIPData
}

func (m *mockWafServicePutGeoIPDataServer) Recv() (rec *pb.GeoIPData, err error) {
	if len(m.messages) == 0 {
		err = io.EOF
		return
	}

	rec = m.messages[0]
	m.messages = m.messages[1:]
	return
}

func (m *mockWafServicePutGeoIPDataServer) SendAndClose(*pb.PutGeoIPDataResponse) error {
	return nil
}

func (m *mockWafServer) SetLogMetaData(l waf.ConfigLogMetaData) {
}

func (m *mockWafServer) PutIPReputationList(ips []string) {
	m.putIPReputationListCalled++
}
