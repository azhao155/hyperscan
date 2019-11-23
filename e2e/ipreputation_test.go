package e2e

import (
	pb "azwaf/proto"
	"context"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"

	"testing"
)

func TestPutIPReputationList(t *testing.T) {
	assert := assert.New(t)
	startServer(t)
	c := newWafServiceClient(t)
	ctx := context.Background()

	irStream, err := c.PutIPReputationList(ctx, grpc.WaitForReady(true))
	assert.Nil(err)

	err = irStream.Send(&pb.IpReputationList{
		Ip: []string{"0.0.0.0/32=bot:1", "1.2.3.4/32=bot:1"},
	})
	assert.Nil(err)

	_, err = irStream.CloseAndRecv()
	assert.Nil(err)
}

func TestIPReputationEngineBlockedRequest(t *testing.T) {
	assert := assert.New(t)
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
	assert.Nil(err)

	irStream, err := c.PutIPReputationList(ctx, grpc.WaitForReady(true))
	assert.Nil(err)

	err = irStream.Send(&pb.IpReputationList{
		Ip: []string{"0.0.0.0/32=bot:1", "1.2.3.4/32=bot:1"},
	})
	assert.Nil(err)

	_, err = irStream.CloseAndRecv()
	assert.Nil(err)

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

	wafDecision := evalRequest(ctx, t, c, r)
	assert.Equal(wafDecision.Action, pb.WafDecision_BLOCK, "IPReputationEngine failed to catch malicious request")
}

func TestIPReputationEngineDetectionMode(t *testing.T) {
	assert := assert.New(t)
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
	assert.Nil(err)

	irStream, err := c.PutIPReputationList(ctx, grpc.WaitForReady(true))
	assert.Nil(err)

	err = irStream.Send(&pb.IpReputationList{
		Ip: []string{"0.0.0.0/32=bot:1", "1.2.3.4/32=bot:1"},
	})
	assert.Nil(err)

	_, err = irStream.CloseAndRecv()
	assert.Nil(err)

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

	wafDecision := evalRequest(ctx, t, c, r)
	assert.Equal(wafDecision.Action, pb.WafDecision_PASS, "IPReputationEngine blocked a request in Detection Mode")
}

func TestIPReputationEngineLogPresence(t *testing.T) {
	assert := assert.New(t)
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
	assert.Nil(err)

	irStream, err := c.PutIPReputationList(ctx, grpc.WaitForReady(true))

	err = irStream.Send(&pb.IpReputationList{
		Ip: []string{"0.0.0.0/32=bot:1", "1.2.3.4/32=bot:1"},
	})
	assert.Nil(err)

	_, err = irStream.CloseAndRecv()
	assert.Nil(err)

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

	evalRequest(ctx, t, c, r)

	logs := readLogs(t)
	assert.Equal(len(logs), 1, "Invalid number of logs for IPReputationTriggered")

	log := logs[0]

	assert.Contains(log, "IPReputationTriggered", "IPReputation log is malformed")
	assert.Contains(log, "Detected", "IPReputation log is malformed")
}

func TestIPReputationEngineBenignRequest(t *testing.T) {
	assert := assert.New(t)
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
	assert.Nil(err)

	irStream, err := c.PutIPReputationList(ctx, grpc.WaitForReady(true))
	assert.Nil(err)

	err = irStream.Send(&pb.IpReputationList{
		Ip: []string{"0.0.0.0/32=bot:1", "1.2.3.4/32=bot:1"},
	})
	assert.Nil(err)

	_, err = irStream.CloseAndRecv()
	assert.Nil(err)

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

	wafDecision := evalRequest(ctx, t, c, r)
	assert.Equal(wafDecision.Action, pb.WafDecision_PASS, "IPReputationEngine failed to pass benign request")
}
