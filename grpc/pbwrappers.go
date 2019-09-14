package grpc

import (
	pb "azwaf/proto"
	"azwaf/waf"
	"fmt"
	"io"

	"github.com/golang/protobuf/jsonpb"
)

type wafHTTPRequestPbWrapper struct {
	pb            *pb.HeadersAndFirstChunk
	bodyReader    *wafHTTPRequestPbWrapperBodyReader
	transactionID string
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
func (r *wafHTTPRequestPbWrapper) TransactionID() string { return r.transactionID }
func (r *wafHTTPRequestPbWrapper) RemoteAddr() string    { return r.pb.RemoteAddr }

// TODO once protobuf has config id, need to be implemented
func (r *wafHTTPRequestPbWrapper) ConfigID() string { return r.pb.ConfigID }

func (r *wafHTTPRequestPbWrapper) LogMetaData() waf.RequestLogMetaData {
	return &requestLogMetaDataPbWrapper{pb: r.pb.MetaData}
}

type headerPairPbWrapper struct{ pb *pb.HeaderPair }

func (h *headerPairPbWrapper) Key() string   { return h.pb.Key }
func (h *headerPairPbWrapper) Value() string { return h.pb.Value }

type requestLogMetaDataPbWrapper struct{ pb *pb.RequestLogMetaData }

func (h *requestLogMetaDataPbWrapper) Scope() string     { return h.pb.Scope }
func (h *requestLogMetaDataPbWrapper) ScopeName() string { return h.pb.ScopeName }

type wafHTTPRequestPbWrapperBodyReader struct {
	readCb func(p []byte) (n int, err error)
}

func (r *wafHTTPRequestPbWrapperBodyReader) Read(p []byte) (n int, err error) { return r.readCb(p) }

type secRuleConfigImpl struct{ pb *pb.SecRuleConfig }

func (c *secRuleConfigImpl) Enabled() bool     { return c.pb.Enabled }
func (c *secRuleConfigImpl) RuleSetID() string { return c.pb.RuleSetId }

type customRuleConfigImpl struct{ pb *pb.CustomRuleConfig }

func (cc *customRuleConfigImpl) CustomRules() []waf.CustomRule {
	customRules := make([]waf.CustomRule, 0)
	for _, cr := range cc.pb.CustomRules {
		customRules = append(customRules, &customRuleWrapper{pb: cr})
	}
	return customRules
}

type ipReputationConfigImpl struct{ pb *pb.IPReputationConfig }

func (c *ipReputationConfigImpl) Enabled() bool { return c.pb.Enabled }

type policyConfigWrapper struct{ pb *pb.PolicyConfig }

func (c *policyConfigWrapper) ConfigID() string { return c.pb.ConfigID }
func (c *policyConfigWrapper) SecRuleConfig() waf.SecRuleConfig {
	return &secRuleConfigImpl{pb: c.pb.SecRuleConfig}
}
func (c *policyConfigWrapper) CustomRuleConfig() waf.CustomRuleConfig {
	return &customRuleConfigImpl{pb: c.pb.CustomRuleConfig}
}
func (c *policyConfigWrapper) IPReputationConfig() waf.IPReputationConfig {
	return &ipReputationConfigImpl{pb: c.pb.IpReputationConfig}
}

type configLogMetaDataPbWrapper struct{ pb *pb.ConfigLogMetaData }

func (h *configLogMetaDataPbWrapper) ResourceID() string { return h.pb.ResourceID }
func (h *configLogMetaDataPbWrapper) InstanceID() string { return h.pb.InstanceID }

type customRuleWrapper struct{ pb *pb.CustomRule }

func (cr *customRuleWrapper) Name() string     { return cr.pb.Name }
func (cr *customRuleWrapper) Priority() int    { return int(cr.pb.Priority) }
func (cr *customRuleWrapper) RuleType() string { return cr.pb.RuleType }
func (cr *customRuleWrapper) MatchConditions() []waf.MatchCondition {
	matchConditions := make([]waf.MatchCondition, 0)
	for _, mc := range cr.pb.MatchConditions {
		matchConditions = append(matchConditions, &matchConditionWrapper{pb: mc})
	}
	return matchConditions
}
func (cr *customRuleWrapper) Action() string { return cr.pb.Action }

type matchConditionWrapper struct {
	pb *pb.MatchCondition
}

func (mc *matchConditionWrapper) MatchVariables() []waf.MatchVariable {
	matchVariables := make([]waf.MatchVariable, 0)
	for _, mv := range mc.pb.MatchVariables {
		matchVariables = append(matchVariables, &matchVariableWrapper{pb: mv})
	}
	return matchVariables
}

func (mc *matchConditionWrapper) Operator() string { return mc.pb.Operator }

func (mc *matchConditionWrapper) NegateCondition() bool { return mc.pb.NegateCondition }

func (mc *matchConditionWrapper) MatchValues() []string {
	matchValues := make([]string, 0)
	for _, mv := range mc.pb.MatchValues {
		matchValues = append(matchValues, mv)
	}
	return matchValues
}

func (mc *matchConditionWrapper) Transforms() []string {
	transforms := make([]string, 0)
	for _, t := range mc.pb.Transforms {
		transforms = append(transforms, t)
	}
	return transforms
}

type matchVariableWrapper struct {
	pb *pb.MatchVariable
}

func (mv *matchVariableWrapper) VariableName() string { return mv.pb.VariableName }
func (mv *matchVariableWrapper) Selector() string     { return mv.pb.Selector }

type configPbWrapper struct{ pb *pb.WAFConfig }

func (c *configPbWrapper) ConfigVersion() int32 { return c.pb.ConfigVersion }
func (c *configPbWrapper) PolicyConfigs() []waf.PolicyConfig {
	ss := make([]waf.PolicyConfig, 0)
	for _, p := range c.pb.PolicyConfigs {
		ss = append(ss, &policyConfigWrapper{pb: p})
	}
	return ss
}

func (c *configPbWrapper) LogMetaData() waf.ConfigLogMetaData {
	return &configLogMetaDataPbWrapper{pb: c.pb.MetaData}
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
