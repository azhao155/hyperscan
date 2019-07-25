package grpc

import (
	pb "azwaf/proto"
	"azwaf/waf"
	"fmt"
	"io"

	"github.com/golang/protobuf/jsonpb"
)

type wafHTTPRequestPbWrapper struct {
	pb         *pb.HeadersAndFirstChunk
	bodyReader *wafHTTPRequestPbWrapperBodyReader
}

func (r *wafHTTPRequestPbWrapper) Method() string { return r.pb.Method }
func (r *wafHTTPRequestPbWrapper) URI() string    { return r.pb.Uri }
func (r *wafHTTPRequestPbWrapper) Headers() []waf.HeaderPair {
	hh := make([]waf.HeaderPair, 0, len(r.pb.Headers))
	for _, ph := range r.pb.Headers {
		hh = append(hh, &headerPairPbWrapper{pb: ph})
	}
	return hh
}
func (r *wafHTTPRequestPbWrapper) BodyReader() io.Reader { return r.bodyReader }

// TODO once protobuf has config id, need to be implemented
func (r *wafHTTPRequestPbWrapper) SecRuleConfigID() string { return r.pb.SecRuleConfigID }

type headerPairPbWrapper struct{ pb *pb.HeaderPair }

func (h *headerPairPbWrapper) Key() string   { return h.pb.Key }
func (h *headerPairPbWrapper) Value() string { return h.pb.Value }

type wafHTTPRequestPbWrapperBodyReader struct {
	readCb func(p []byte) (n int, err error)
}

func (r *wafHTTPRequestPbWrapperBodyReader) Read(p []byte) (n int, err error) { return r.readCb(p) }

type secRuleConfigImpl struct{ pb *pb.SecRuleConfig }

func (c *secRuleConfigImpl) ID() string        { return c.pb.Id }
func (c *secRuleConfigImpl) Enabled() bool     { return c.pb.Enabled }
func (c *secRuleConfigImpl) RuleSetID() string { return c.pb.RuleSetId }

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

// ConfigConverterImpl implement config SerializeToJSON/DeSerializeFromJSON.
type ConfigConverterImpl struct{}

// SerializeToJSON serializes a WAFConfig to a JSON string. Only works if the WAFConfig is a configPbWrapper wrapping a protobuf.
func (*ConfigConverterImpl) SerializeToJSON(c waf.Config) (json string, err error) {
	wci, ok := c.(*configPbWrapper)
	if !ok {
		err = fmt.Errorf("Failed convert given WAFConfig to a serializable protobuf backed type")
	}

	m := jsonpb.Marshaler{}
	json, err = m.MarshalToString(wci.pb)
	return
}

// DeserializeFromJSON converts JSON to a WAF config object
func (*ConfigConverterImpl) DeserializeFromJSON(str string) (c waf.Config, err error) {
	var pb pb.WAFConfig
	err = jsonpb.UnmarshalString(str, &pb)
	if err != nil {
		return
	}

	c = &configPbWrapper{pb: &pb}
	return
}
