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

func (r *wafHTTPRequestPbWrapper) TransactionID() string { return r.pb.TransactionID }
func (r *wafHTTPRequestPbWrapper) Method() string        { return r.pb.Method }
func (r *wafHTTPRequestPbWrapper) URI() string           { return r.pb.Uri }
func (r *wafHTTPRequestPbWrapper) Protocol() string      { return r.pb.Protocol }
func (r *wafHTTPRequestPbWrapper) RemoteAddr() string    { return r.pb.RemoteAddr }
func (r *wafHTTPRequestPbWrapper) Headers() []waf.HeaderPair {
	hh := make([]waf.HeaderPair, 0, len(r.pb.Headers))
	for _, ph := range r.pb.Headers {
		hh = append(hh, &headerPairPbWrapper{pb: ph})
	}
	return hh
}
func (r *wafHTTPRequestPbWrapper) BodyReader() io.Reader { return r.bodyReader }

// TODO once protobuf has config id, need to be implemented
func (r *wafHTTPRequestPbWrapper) ConfigID() string { return r.pb.ConfigID }

func (r *wafHTTPRequestPbWrapper) LogMetaData() waf.RequestLogMetaData {
	if r.pb.MetaData == nil {
		return nil
	}

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

type customRuleConfigImpl struct {
	pb               *pb.CustomRuleConfig
	customRulesCache []waf.CustomRule
}

func (cc *customRuleConfigImpl) CustomRules() []waf.CustomRule {
	if cc.customRulesCache == nil {
		for _, cr := range cc.pb.CustomRules {
			crWrapped := &customRuleWrapper{pb: cr}
			cc.customRulesCache = append(cc.customRulesCache, crWrapped)
		}
	}

	return cc.customRulesCache
}

type ipReputationConfigImpl struct{ pb *pb.IPReputationConfig }

func (c *ipReputationConfigImpl) Enabled() bool { return c.pb.Enabled }

type policyConfigWrapper struct{ pb *pb.PolicyConfig }

func (c *policyConfigWrapper) ConfigID() string      { return c.pb.ConfigID }
func (c *policyConfigWrapper) IsDetectionMode() bool { return c.pb.IsDetectionMode }
func (c *policyConfigWrapper) IsShadowMode() bool    { return c.pb.IsShadowMode }
func (c *policyConfigWrapper) SecRuleConfig() waf.SecRuleConfig {
	if c.pb.SecRuleConfig == nil {
		return nil
	}

	return &secRuleConfigImpl{pb: c.pb.SecRuleConfig}
}
func (c *policyConfigWrapper) CustomRuleConfig() waf.CustomRuleConfig {
	if c.pb.CustomRuleConfig == nil {
		return nil
	}

	return &customRuleConfigImpl{pb: c.pb.CustomRuleConfig}
}

type geoIPDataRecordWrapper struct{ pb *pb.GeoIPDataRecord }

func (rec *geoIPDataRecordWrapper) StartIP() uint32     { return rec.pb.StartIP }
func (rec *geoIPDataRecordWrapper) EndIP() uint32       { return rec.pb.EndIP }
func (rec *geoIPDataRecordWrapper) CountryCode() string { return rec.pb.CountryCode }

func (c *policyConfigWrapper) IPReputationConfig() waf.IPReputationConfig {
	if c.pb.IpReputationConfig == nil {
		return nil
	}
	return &ipReputationConfigImpl{pb: c.pb.IpReputationConfig}
}

type configLogMetaDataPbWrapper struct{ pb *pb.ConfigLogMetaData }

func (h *configLogMetaDataPbWrapper) ResourceID() string { return h.pb.ResourceID }
func (h *configLogMetaDataPbWrapper) InstanceID() string { return h.pb.InstanceID }

type customRuleWrapper struct {
	pb                   *pb.CustomRule
	matchConditionsCache []waf.MatchCondition
}

func (cr *customRuleWrapper) Name() string     { return cr.pb.Name }
func (cr *customRuleWrapper) Priority() int    { return int(cr.pb.Priority) }
func (cr *customRuleWrapper) RuleType() string { return cr.pb.RuleType }
func (cr *customRuleWrapper) MatchConditions() []waf.MatchCondition {
	if cr.matchConditionsCache == nil {
		for _, mc := range cr.pb.MatchConditions {
			mcWrapped := &matchConditionWrapper{pb: mc}
			cr.matchConditionsCache = append(cr.matchConditionsCache, mcWrapped)
		}
	}
	return cr.matchConditionsCache
}
func (cr *customRuleWrapper) Action() string { return cr.pb.Action }

type matchConditionWrapper struct {
	pb                  *pb.MatchCondition
	matchVariablesCache []waf.MatchVariable
	matchValuesCache    []string
	transformsCache     []string
}

func (mc *matchConditionWrapper) MatchVariables() []waf.MatchVariable {
	if mc.matchVariablesCache == nil {
		for _, mv := range mc.pb.MatchVariables {
			mvWrapped := &matchVariableWrapper{pb: mv}
			mc.matchVariablesCache = append(mc.matchVariablesCache, mvWrapped)
		}
	}
	return mc.matchVariablesCache
}

func (mc *matchConditionWrapper) Operator() string { return mc.pb.Operator }

func (mc *matchConditionWrapper) NegateCondition() bool { return mc.pb.NegateCondition }

func (mc *matchConditionWrapper) MatchValues() []string {
	if mc.matchValuesCache == nil {
		for _, mv := range mc.pb.MatchValues {
			mc.matchValuesCache = append(mc.matchValuesCache, mv)
		}
	}
	return mc.matchValuesCache
}

func (mc *matchConditionWrapper) Transforms() []string {
	if mc.transformsCache == nil {
		for _, t := range mc.pb.Transforms {
			mc.transformsCache = append(mc.transformsCache, t)
		}
	}
	return mc.transformsCache
}

type matchVariableWrapper struct {
	pb *pb.MatchVariable
}

func (mv *matchVariableWrapper) VariableName() string { return mv.pb.VariableName }
func (mv *matchVariableWrapper) Selector() string     { return mv.pb.Selector }

type configPbWrapper struct {
	pb                 *pb.WAFConfig
	policyConfigsCache []waf.PolicyConfig
}

func (c *configPbWrapper) ConfigVersion() int32 { return c.pb.ConfigVersion }
func (c *configPbWrapper) PolicyConfigs() []waf.PolicyConfig {
	if c.policyConfigsCache == nil {
		for _, p := range c.pb.PolicyConfigs {
			policyWrapped := &policyConfigWrapper{pb: p}
			c.policyConfigsCache = append(c.policyConfigsCache, policyWrapped)
		}
	}
	return c.policyConfigsCache
}

func (c *configPbWrapper) LogMetaData() waf.ConfigLogMetaData {
	if c.pb.MetaData == nil {
		return nil
	}

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
