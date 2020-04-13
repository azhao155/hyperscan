package e2e

import (
	pb "azwaf/proto"
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

func TestRequestBodySizeLimitInKbBlocked(t *testing.T) {
	assert := assert.New(t)
	startServer(t)
	c := newWafServiceClient(t)
	ctx := context.Background()

	const configID = "abc"
	config := &pb.WAFConfig{
		ConfigVersion: 1,
		PolicyConfigs: []*pb.PolicyConfig{
			&pb.PolicyConfig{
				ConfigID:                 configID,
				IsDetectionMode:          false,
				RequestBodySizeLimitInKb: 128,
				RequestBodyCheck:         true,
			},
		},
	}

	_, err := c.PutConfig(ctx, config, grpc.WaitForReady(true))
	assert.Nil(err)

	bodyChunk := []byte("[" + strings.Repeat(`"a",`, (128*1024)/4) + `"a"]`) // Divide by 4 since there are 4 characters that are repeated
	uri := "/index.php?hello=world"
	remoteAddr := "1.2.3.4"
	headers := []*pb.HeaderPair{
		&pb.HeaderPair{
			Key:   "Content-Length",
			Value: strconv.Itoa(len(bodyChunk)),
		},
		&pb.HeaderPair{
			Key:   "Content-Type",
			Value: "application/json",
		},
	}
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
	assert.Equal(pb.WafDecision_BLOCK, wafDecision.Action, "Body parser length limits allowed request above the request body size limit")
}

func TestRequestBodySizeLimitInKbBlockedMultiChunks(t *testing.T) {
	assert := assert.New(t)
	startServer(t)
	c := newWafServiceClient(t)
	ctx := context.Background()

	const configID = "abc"
	config := &pb.WAFConfig{
		ConfigVersion: 1,
		PolicyConfigs: []*pb.PolicyConfig{
			&pb.PolicyConfig{
				ConfigID:                 configID,
				IsDetectionMode:          false,
				RequestBodySizeLimitInKb: 128,
				RequestBodyCheck:         true,
			},
		},
	}

	_, err := c.PutConfig(ctx, config, grpc.WaitForReady(true))
	assert.Nil(err)

	bodyChunk1 := []byte("[" + strings.Repeat(`"a",`, (64*1024)/4) + `"a"]`) // Divide by 4 since there are 4 characters that are repeated
	bodyChunk2 := []byte("[" + strings.Repeat(`"a",`, (64*1024)/4) + `"a"]`) // Divide by 4 since there are 4 characters that are repeated
	uri := "/index.php?hello=world"
	remoteAddr := "1.2.3.4"
	headers := []*pb.HeaderPair{
		&pb.HeaderPair{
			Key:   "Content-Length",
			Value: strconv.Itoa(len(bodyChunk1) + len(bodyChunk2)),
		},
		&pb.HeaderPair{
			Key:   "Content-Type",
			Value: "application/json",
		},
	}
	moreBodyChunks := true

	r1 := &pb.WafHttpRequest{
		Content: &pb.WafHttpRequest_HeadersAndFirstChunk{
			HeadersAndFirstChunk: &pb.HeadersAndFirstChunk{
				Uri:            uri,
				Headers:        headers,
				RemoteAddr:     remoteAddr,
				FirstBodyChunk: bodyChunk1,
				MoreBodyChunks: moreBodyChunks,
				ConfigID:       configID,
			},
		},
	}

	r2 := &pb.WafHttpRequest{
		Content: &pb.WafHttpRequest_NextBodyChunk{
			NextBodyChunk: &pb.NextBodyChunk{
				BodyChunk: bodyChunk2,
			},
		},
	}

	requests := []*pb.WafHttpRequest{ r1, r2}

	wafDecision := evalMultiChunkRequest(ctx, t, c, requests)
	assert.Equal(pb.WafDecision_BLOCK, wafDecision.Action, "Body parser length limits allowed request above the request body size limit")
}

func TestRequestBodySizeLimitInKbAllowed(t *testing.T) {
	assert := assert.New(t)
	startServer(t)
	c := newWafServiceClient(t)
	ctx := context.Background()

	const configID = "abc"
	config := &pb.WAFConfig{
		ConfigVersion: 1,
		PolicyConfigs: []*pb.PolicyConfig{
			&pb.PolicyConfig{
				ConfigID:                 configID,
				IsDetectionMode:          false,
				RequestBodySizeLimitInKb: 128,
				RequestBodyCheck:         true,
			},
		},
	}

	_, err := c.PutConfig(ctx, config, grpc.WaitForReady(true))
	assert.Nil(err)

	bodyChunk := []byte("[" + strings.Repeat(`"a",`, (127*1024)/4) + `"a"]`) // Divide by 4 since there are 4 characters that are repeated
	fmt.Println(len(bodyChunk))
	uri := "/index.php?hello=world"
	remoteAddr := "1.2.3.4"
	headers := []*pb.HeaderPair{
		&pb.HeaderPair{
			Key:   "Content-Length",
			Value: strconv.Itoa(len(bodyChunk)),
		},
		&pb.HeaderPair{
			Key:   "Content-Type",
			Value: "application/json",
		},
	}
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
	assert.Equal(pb.WafDecision_PASS, wafDecision.Action, "Body parser length limits blocked request below the request body size limit")
}

func TestRequestBodySizeLimitInKbAllowedMultiChunks(t *testing.T) {
	assert := assert.New(t)
	startServer(t)
	c := newWafServiceClient(t)
	ctx := context.Background()

	const configID = "abc"
	config := &pb.WAFConfig{
		ConfigVersion: 1,
		PolicyConfigs: []*pb.PolicyConfig{
			&pb.PolicyConfig{
				ConfigID:                 configID,
				IsDetectionMode:          false,
				RequestBodySizeLimitInKb: 128,
				RequestBodyCheck:         true,
			},
		},
	}

	_, err := c.PutConfig(ctx, config, grpc.WaitForReady(true))
	assert.Nil(err)

	bodyChunk1 := []byte("[" + strings.Repeat(`"a",`, (64*1024)/4) + `"a"]`) // Divide by 4 since there are 4 characters that are repeated
	bodyChunk2 := []byte("[" + strings.Repeat(`"a",`, (63*1024)/4) + `"a"]`) // Divide by 4 since there are 4 characters that are repeated
	uri := "/index.php?hello=world"
	remoteAddr := "1.2.3.4"
	headers := []*pb.HeaderPair{
		&pb.HeaderPair{
			Key:   "Content-Length",
			Value: strconv.Itoa(len(bodyChunk1) + len(bodyChunk2)),
		},
		&pb.HeaderPair{
			Key:   "Content-Type",
			Value: "application/json",
		},
	}
	moreBodyChunks := true

	r1 := &pb.WafHttpRequest{
		Content: &pb.WafHttpRequest_HeadersAndFirstChunk{
			HeadersAndFirstChunk: &pb.HeadersAndFirstChunk{
				Uri:            uri,
				Headers:        headers,
				RemoteAddr:     remoteAddr,
				FirstBodyChunk: bodyChunk1,
				MoreBodyChunks: moreBodyChunks,
				ConfigID:       configID,
			},
		},
	}

	r2 := &pb.WafHttpRequest{
		Content: &pb.WafHttpRequest_NextBodyChunk{
			NextBodyChunk: &pb.NextBodyChunk{
				BodyChunk: bodyChunk2,
			},
		},
	}

	requests := []*pb.WafHttpRequest{ r1, r2}

	wafDecision := evalMultiChunkRequest(ctx, t, c, requests)
	assert.Equal(pb.WafDecision_PASS, wafDecision.Action, "Body parser length limits blocked request below the request body size limit")
}