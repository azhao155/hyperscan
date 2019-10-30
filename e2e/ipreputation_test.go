package e2e

import (
	pb "azwaf/proto"
	"context"

	"google.golang.org/grpc"

	"strings"
	"testing"
)

func TestPutIPReputationList(t *testing.T) {
	startServer(t)
	c := newWafServiceClient(t)
	ctx := context.Background()

	irStream, err := c.PutIPReputationList(ctx, grpc.WaitForReady(true))
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	err = irStream.Send(&pb.IpReputationList{
		Ip: []string{"0.0.0.0/32=bot:1", "1.2.3.4/32=bot:1"},
	})
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	_, err = irStream.CloseAndRecv()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}
}

func TestBlockedRequest(t *testing.T) {
	startServer(t)
	c := newWafServiceClient(t)
	ctx := context.Background()

	const configID = "abc"
	config := &pb.WAFConfig{
		ConfigVersion: 1,
		PolicyConfigs: []*pb.PolicyConfig{
			&pb.PolicyConfig{
				ConfigID:        configID,
				IsDetectionMode: false,
				IpReputationConfig: &pb.IPReputationConfig{
					Enabled: true,
				},
			},
		},
	}

	_, err := c.PutConfig(ctx, config, grpc.WaitForReady(true))
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	irStream, err := c.PutIPReputationList(ctx, grpc.WaitForReady(true))
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	err = irStream.Send(&pb.IpReputationList{
		Ip: []string{"0.0.0.0/32=bot:1", "1.2.3.4/32=bot:1"},
	})
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	_, err = irStream.CloseAndRecv()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	erStream, err := c.EvalRequest(ctx, grpc.WaitForReady(true))
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	uri := "/index.php?hello=world"
	remoteAddr := "1.2.3.4"
	var headers []*pb.HeaderPair
	var bodyChunk []byte
	moreBodyChunks := false

	r := &pb.WafHttpRequest{
		Content: &pb.WafHttpRequest_HeadersAndFirstChunk{
			HeadersAndFirstChunk: &pb.HeadersAndFirstChunk{
				Uri:            uri,
				Headers:        headers,
				RemoteAddr:     remoteAddr,
				FirstBodyChunk: bodyChunk,
				MoreBodyChunks: moreBodyChunks,
				ConfigID:       configID,
			},
		},
	}

	err = erStream.Send(r)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	wafDecision, err := erStream.CloseAndRecv()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	if wafDecision.Action != pb.WafDecision_BLOCK {
		t.Fatal("IPReputationEngine failed to catch malicious request")
	}
}

func TestDetectionMode(t *testing.T) {
	startServer(t)
	c := newWafServiceClient(t)
	ctx := context.Background()

	const configID = "abc"
	config := &pb.WAFConfig{
		ConfigVersion: 1,
		PolicyConfigs: []*pb.PolicyConfig{
			&pb.PolicyConfig{
				ConfigID:        configID,
				IsDetectionMode: true,
				IpReputationConfig: &pb.IPReputationConfig{
					Enabled: true,
				},
			},
		},
	}

	_, err := c.PutConfig(ctx, config, grpc.WaitForReady(true))
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	irStream, err := c.PutIPReputationList(ctx, grpc.WaitForReady(true))
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	err = irStream.Send(&pb.IpReputationList{
		Ip: []string{"0.0.0.0/32=bot:1", "1.2.3.4/32=bot:1"},
	})
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	_, err = irStream.CloseAndRecv()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	erStream, err := c.EvalRequest(ctx, grpc.WaitForReady(true))
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	uri := "/index.php?hello=world"
	remoteAddr := "1.2.3.4"
	var headers []*pb.HeaderPair
	var bodyChunk []byte
	moreBodyChunks := false

	r := &pb.WafHttpRequest{
		Content: &pb.WafHttpRequest_HeadersAndFirstChunk{
			HeadersAndFirstChunk: &pb.HeadersAndFirstChunk{
				Uri:            uri,
				Headers:        headers,
				RemoteAddr:     remoteAddr,
				FirstBodyChunk: bodyChunk,
				MoreBodyChunks: moreBodyChunks,
				ConfigID:       configID,
			},
		},
	}

	err = erStream.Send(r)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	wafDecision, err := erStream.CloseAndRecv()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	if wafDecision.Action != pb.WafDecision_PASS {
		t.Fatal("IPReputationEngine blocked a request in Detection Mode")
	}
}

func TestLogPresence(t *testing.T) {
	startServer(t)
	c := newWafServiceClient(t)
	ctx := context.Background()

	const configID = "abc"
	config := &pb.WAFConfig{
		ConfigVersion: 1,
		PolicyConfigs: []*pb.PolicyConfig{
			&pb.PolicyConfig{
				ConfigID:        configID,
				IsDetectionMode: true,
				IpReputationConfig: &pb.IPReputationConfig{
					Enabled: true,
				},
			},
		},
	}
	_, err := c.PutConfig(ctx, config, grpc.WaitForReady(true))
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	irStream, err := c.PutIPReputationList(ctx, grpc.WaitForReady(true))

	err = irStream.Send(&pb.IpReputationList{
		Ip: []string{"0.0.0.0/32=bot:1", "1.2.3.4/32=bot:1"},
	})
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	_, err = irStream.CloseAndRecv()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	erStream, err := c.EvalRequest(ctx, grpc.WaitForReady(true))
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	uri := "/index.php?hello=world"
	remoteAddr := "1.2.3.4"
	var headers []*pb.HeaderPair
	var bodyChunk []byte
	moreBodyChunks := false

	r := &pb.WafHttpRequest{
		Content: &pb.WafHttpRequest_HeadersAndFirstChunk{
			HeadersAndFirstChunk: &pb.HeadersAndFirstChunk{
				Uri:            uri,
				Headers:        headers,
				RemoteAddr:     remoteAddr,
				FirstBodyChunk: bodyChunk,
				MoreBodyChunks: moreBodyChunks,
				ConfigID:       configID,
			},
		},
	}

	clearLogs(t)

	err = erStream.Send(r)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	_, err = erStream.CloseAndRecv()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	logs := readLogs(t)
	if len(logs) != 1 {
		t.Fatalf("Invalid number of logs for IPReputationTriggered")
	}
	log := logs[0]
	if !strings.Contains(log, "IPReputationTriggered") || !strings.Contains(log, "Detected") {
		t.Fatalf("IPReputation log is malformed")
	}
}

func TestAllowedRequest(t *testing.T) {
	startServer(t)
	c := newWafServiceClient(t)
	ctx := context.Background()

	const configID = "abc"

	config := &pb.WAFConfig{
		ConfigVersion: 1,
		PolicyConfigs: []*pb.PolicyConfig{
			&pb.PolicyConfig{
				ConfigID:        configID,
				IsDetectionMode: false,
				IpReputationConfig: &pb.IPReputationConfig{
					Enabled: true,
				},
			},
		},
	}
	_, err := c.PutConfig(ctx, config, grpc.WaitForReady(true))
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	irStream, err := c.PutIPReputationList(ctx, grpc.WaitForReady(true))
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	err = irStream.Send(&pb.IpReputationList{
		Ip: []string{"0.0.0.0/32=bot:1", "1.2.3.4/32=bot:1"},
	})
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	_, err = irStream.CloseAndRecv()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	erStream, err := c.EvalRequest(ctx, grpc.WaitForReady(true))
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	uri := "/index.php?hello=world"
	remoteAddr := "32.32.32.32"
	var headers []*pb.HeaderPair
	var bodyChunk []byte
	moreBodyChunks := false

	r := &pb.WafHttpRequest{
		Content: &pb.WafHttpRequest_HeadersAndFirstChunk{
			HeadersAndFirstChunk: &pb.HeadersAndFirstChunk{
				Uri:            uri,
				Headers:        headers,
				RemoteAddr:     remoteAddr,
				FirstBodyChunk: bodyChunk,
				MoreBodyChunks: moreBodyChunks,
				ConfigID:       configID,
			},
		},
	}

	err = erStream.Send(r)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	wafDecision, err := erStream.CloseAndRecv()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	if wafDecision.Action != pb.WafDecision_PASS {
		t.Fatal("IPReputationEngine failed to allow benign request")
	}
}
