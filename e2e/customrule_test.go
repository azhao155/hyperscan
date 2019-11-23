package e2e

import (
	pb "azwaf/proto"
	"context"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"

	"testing"
)

const configID = "abc"

var geoBlacklistRule = &pb.CustomRule{
	Name:     "geoBlacklistRule",
	Priority: 3,
	RuleType: "MatchRule",
	MatchConditions: []*pb.MatchCondition{
		&pb.MatchCondition{
			MatchVariables: []*pb.MatchVariable{
				&pb.MatchVariable{
					VariableName: "RemoteAddr",
				},
				&pb.MatchVariable{
					VariableName: "RequestHeaders",
					Selector:     "X-Forwarded-For",
				},
			},
			Operator:        "GeoMatch",
			NegateCondition: false,
			MatchValues:     []string{"AB", "CD", "EF"},
		},
	},
	Action: "Block",
}

var geoIPData = &pb.GeoIPData{
	GeoIPDataRecords: []*pb.GeoIPDataRecord{
		&pb.GeoIPDataRecord{StartIP: 0x00000000, EndIP: 0x9fffffff, CountryCode: "OK"},
		&pb.GeoIPDataRecord{StartIP: 0xa0000000, EndIP: 0xbfffffff, CountryCode: "AB"},
		&pb.GeoIPDataRecord{StartIP: 0xc0000000, EndIP: 0xdfffffff, CountryCode: "CD"},
		&pb.GeoIPDataRecord{StartIP: 0xe0000000, EndIP: 0xffffffff, CountryCode: "EF"},
	},
}

func TestPutGeoIpData(t *testing.T) {
	assert := assert.New(t)
	startServer(t)
	c := newWafServiceClient(t)
	ctx := context.Background()

	giStream, err := c.PutGeoIPData(ctx, grpc.WaitForReady(true))
	assert.Nil(err)

	err = giStream.Send(geoIPData)
	assert.Nil(err)

	_, err = giStream.CloseAndRecv()
	assert.Nil(err)

}

func TestCustomRuleEngineBlockedRequest(t *testing.T) {
	assert := assert.New(t)
	startServer(t)
	c := newWafServiceClient(t)
	ctx := context.Background()

	config := &pb.WAFConfig{
		ConfigVersion: 1,
		PolicyConfigs: []*pb.PolicyConfig{
			&pb.PolicyConfig{
				ConfigID:        configID,
				IsDetectionMode: false,
				CustomRuleConfig: &pb.CustomRuleConfig{
					CustomRules: []*pb.CustomRule{
						geoBlacklistRule,
					},
				},
			},
		},
	}

	_, err := c.PutConfig(ctx, config, grpc.WaitForReady(true))
	assert.Nil(err)

	giStream, err := c.PutGeoIPData(ctx, grpc.WaitForReady(true))
	assert.Nil(err)

	err = giStream.Send(geoIPData)
	assert.Nil(err)

	_, err = giStream.CloseAndRecv()
	assert.Nil(err)

	uri := "/index.php?hello=world"
	// 255.255.255.255 == 0xffffffff => "EF", blocked.
	remoteAddr := "255.255.255.255"
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
	assert.Equal(wafDecision.Action, pb.WafDecision_BLOCK, "CustomRulesEngine failed to block malicious request")
}

func TestCustomRuleEngineDetectionMode(t *testing.T) {
	assert := assert.New(t)
	startServer(t)
	c := newWafServiceClient(t)
	ctx := context.Background()

	config := &pb.WAFConfig{
		ConfigVersion: 1,
		PolicyConfigs: []*pb.PolicyConfig{
			&pb.PolicyConfig{
				ConfigID:        configID,
				IsDetectionMode: true,
				CustomRuleConfig: &pb.CustomRuleConfig{
					CustomRules: []*pb.CustomRule{
						geoBlacklistRule,
					},
				},
			},
		},
	}

	_, err := c.PutConfig(ctx, config, grpc.WaitForReady(true))
	assert.Nil(err)

	giStream, err := c.PutGeoIPData(ctx, grpc.WaitForReady(true))
	assert.Nil(err)

	err = giStream.Send(geoIPData)
	assert.Nil(err)

	_, err = giStream.CloseAndRecv()
	assert.Nil(err)

	uri := "/index.php?hello=world"
	// 255.255.255.255 == 0xffffffff => "EF", blocked.
	remoteAddr := "255.255.255.255"
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
	assert.Equal(wafDecision.Action, pb.WafDecision_PASS, "CustomRulesEngine blocked a request in Detection Mode")
}

func TestCustomRuleEngineLogPresence(t *testing.T) {
	assert := assert.New(t)
	startServer(t)
	c := newWafServiceClient(t)
	ctx := context.Background()

	config := &pb.WAFConfig{
		ConfigVersion: 1,
		PolicyConfigs: []*pb.PolicyConfig{
			&pb.PolicyConfig{
				ConfigID:        configID,
				IsDetectionMode: true,
				CustomRuleConfig: &pb.CustomRuleConfig{
					CustomRules: []*pb.CustomRule{
						geoBlacklistRule,
					},
				},
			},
		},
	}

	_, err := c.PutConfig(ctx, config, grpc.WaitForReady(true))
	assert.Nil(err)

	giStream, err := c.PutGeoIPData(ctx, grpc.WaitForReady(true))
	assert.Nil(err)

	err = giStream.Send(geoIPData)
	assert.Nil(err)

	_, err = giStream.CloseAndRecv()
	assert.Nil(err)

	uri := "/index.php?hello=world"
	// 255.255.255.255 == 0xffffffff => "EF", blocked.
	remoteAddr := "255.255.255.255"
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
	assert.Equal(len(logs), 1, "Invalid number of logs for CustomRuleTriggered")

	log := logs[0]

	assert.Contains(log, "geoBlacklistRule", "CustomRule log is malformed")
	assert.Contains(log, "Detected", "CustomRule log is malformed")
}

func TestCustomRuleEngineBenignRequest(t *testing.T) {
	assert := assert.New(t)
	startServer(t)
	c := newWafServiceClient(t)
	ctx := context.Background()

	config := &pb.WAFConfig{
		ConfigVersion: 1,
		PolicyConfigs: []*pb.PolicyConfig{
			&pb.PolicyConfig{
				ConfigID:        configID,
				IsDetectionMode: false,
				CustomRuleConfig: &pb.CustomRuleConfig{
					CustomRules: []*pb.CustomRule{
						geoBlacklistRule,
					},
				},
			},
		},
	}

	_, err := c.PutConfig(ctx, config, grpc.WaitForReady(true))
	assert.Nil(err)

	giStream, err := c.PutGeoIPData(ctx, grpc.WaitForReady(true))
	assert.Nil(err)

	err = giStream.Send(geoIPData)
	assert.Nil(err)

	_, err = giStream.CloseAndRecv()
	assert.Nil(err)

	uri := "/index.php?hello=world"
	// 0.0.0.0 == 0x00000000 => "OK", pass.
	remoteAddr := "0.0.0.0"
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
	assert.Equal(wafDecision.Action, pb.WafDecision_PASS, "CustomRulesEngine failed to pass benign request")
}
