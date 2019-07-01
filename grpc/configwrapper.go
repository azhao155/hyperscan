package grpc

import (
	pb "azwaf/proto"
	waf "azwaf/waf"
	"fmt"

	"github.com/golang/protobuf/jsonpb"
)

type secRuleConfigImpl struct{ pb *pb.SecRuleConfig }

func (c *secRuleConfigImpl) ID() string    { return c.pb.Id }
func (c *secRuleConfigImpl) Enabled() bool { return c.pb.Enabled }

type geoDbConfigImpl struct{ pb *pb.GeoDBConfig }

func (c *geoDbConfigImpl) ID() string    { return c.pb.Id }
func (c *geoDbConfigImpl) Enabled() bool { return c.pb.Enabled }

type ipReputationConfigImpl struct{ pb *pb.IPReputationConfig }

func (c *ipReputationConfigImpl) ID() string    { return c.pb.Id }
func (c *ipReputationConfigImpl) Enabled() bool { return c.pb.Enabled }

type configPbWrapper struct{ pb *pb.WAFConfig }

func (c *configPbWrapper) SecRuleConfigs() []waf.SecRuleConfig {
	ss := make([]waf.SecRuleConfig, 0)
	for _, p := range c.pb.SecRuleConfigs {
		ss = append(ss, &secRuleConfigImpl{pb: p})
	}
	return ss
}

func (c *configPbWrapper) GeoDBConfigs() []waf.GeoDBConfig {
	ss := make([]waf.GeoDBConfig, 0)
	for _, p := range c.pb.GeoDBConfigs {
		ss = append(ss, &geoDbConfigImpl{pb: p})
	}
	return ss
}

func (c *configPbWrapper) IPReputationConfigs() []waf.IPReputationConfig {
	ss := make([]waf.IPReputationConfig, 0)
	for _, p := range c.pb.IpReputationConfigs {
		ss = append(ss, &ipReputationConfigImpl{pb: p})
	}
	return ss
}

type configConverterImpl struct{}

// SerializeToJSON serializes a WAFConfig to a JSON string. Only works if the WAFConfig is a configPbWrapper wrapping a protobuf.
func (*configConverterImpl) SerializeToJSON(c waf.Config) (json string, err error) {
	wci, ok := c.(*configPbWrapper)
	if !ok {
		err = fmt.Errorf("Failed convert given WAFConfig to a serializable protobuf backed type")
	}

	m := jsonpb.Marshaler{}
	json, err = m.MarshalToString(wci.pb)
	return
}

// DeSerializeFromJSON converts JSON to a WAF config object
func (*configConverterImpl) DeSerializeFromJSON(str string) (c waf.Config, err error) {
	var pb pb.WAFConfig
	err = jsonpb.UnmarshalString(str, &pb)
	if err != nil {
		return
	}

	c = &configPbWrapper{pb: &pb}
	return
}
