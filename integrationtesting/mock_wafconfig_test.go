package integrationtesting

import (
	"azwaf/waf"
)

type mockWAFConfig struct {
	configVersion int32
	policyConfigs []waf.PolicyConfig
	logMetaData   waf.ConfigLogMetaData
}

func (mc *mockWAFConfig) ConfigVersion() int32 {
	return mc.configVersion
}

func (mc *mockWAFConfig) PolicyConfigs() []waf.PolicyConfig {
	policyConfigs := make([]waf.PolicyConfig, 0)
	for _, pc := range mc.policyConfigs {
		policyConfigs = append(policyConfigs, pc)
	}
	return policyConfigs
}

func (mc *mockWAFConfig) LogMetaData() waf.ConfigLogMetaData {
	return mc.logMetaData
}

type mockPolicyConfig struct {
	configID                 string
	isDetectionMode          bool
	isShadowMode             bool
	requestBodyCheck         bool
	secRuleConfig            waf.SecRuleConfig
	customRuleConfig         waf.CustomRuleConfig
	ipReputationConfig       waf.IPReputationConfig
	fileUploadSizeLimitInMb  int32
	requestBodySizeLimitInKb int32
}

func (mpc *mockPolicyConfig) ConfigID() string {
	return mpc.configID
}

func (mpc *mockPolicyConfig) IsDetectionMode() bool {
	return mpc.isDetectionMode
}

func (mpc *mockPolicyConfig) IsShadowMode() bool {
	return mpc.isShadowMode
}

func (mpc *mockPolicyConfig) RequestBodyCheck() bool {
	return mpc.requestBodyCheck
}

func (mpc *mockPolicyConfig) SecRuleConfig() waf.SecRuleConfig {
	return mpc.secRuleConfig
}

func (mpc *mockPolicyConfig) CustomRuleConfig() waf.CustomRuleConfig {
	return mpc.customRuleConfig
}

func (mpc *mockPolicyConfig) IPReputationConfig() waf.IPReputationConfig {
	return mpc.ipReputationConfig
}

func (mpc *mockPolicyConfig) RequestBodySizeLimitInKb() int32 {
	return mpc.requestBodySizeLimitInKb
}

func (mpc *mockPolicyConfig) FileUploadSizeLimitInMb() int32 {
	return mpc.fileUploadSizeLimitInMb
}

type mockSecRuleConfig struct {
	enabled        bool
	ruleSetID      string
	exclusions     []waf.Exclusion
}

func (msc *mockSecRuleConfig) Enabled() bool                             { return msc.enabled }
func (msc *mockSecRuleConfig) RuleSetID() string                         { return msc.ruleSetID }
func (msc *mockSecRuleConfig) Exclusions() []waf.Exclusion               { return msc.exclusions }

type mockExclusion struct {
	matchVariable         string
	selectorMatchOperator string
	selector              string
	rules                 []int32
}

func (r *mockExclusion) MatchVariable() string         { return r.matchVariable }
func (r *mockExclusion) SelectorMatchOperator() string { return r.selectorMatchOperator }
func (r *mockExclusion) Selector() string              { return r.selector }
func (r *mockExclusion) Rules() []int32 { return r.rules}
type mockCustomRuleConfig struct {
	customRules []waf.CustomRule
}

func (mcc *mockCustomRuleConfig) CustomRules() []waf.CustomRule {
	customRules := make([]waf.CustomRule, 0)
	for _, cr := range mcc.customRules {
		customRules = append(customRules, cr)
	}
	return customRules
}

type mockCustomRule struct {
	name            string
	priority        int
	ruleType        string
	matchConditions []waf.MatchCondition
	action          string
}

func (mcr *mockCustomRule) Name() string     { return mcr.name }
func (mcr *mockCustomRule) Priority() int    { return mcr.priority }
func (mcr *mockCustomRule) RuleType() string { return mcr.ruleType }
func (mcr *mockCustomRule) MatchConditions() []waf.MatchCondition {
	matchConditions := make([]waf.MatchCondition, 0)
	for _, mc := range mcr.matchConditions {
		matchConditions = append(matchConditions, mc)
	}
	return matchConditions
}
func (mcr *mockCustomRule) Action() string { return mcr.action }

type mockMatchCondition struct {
	matchVariables  []waf.MatchVariable
	operator        string
	negateCondition bool
	matchValues     []string
	transforms      []string
}

func (mmc *mockMatchCondition) MatchVariables() []waf.MatchVariable {
	matchVariables := make([]waf.MatchVariable, 0)
	for _, mv := range mmc.matchVariables {
		matchVariables = append(matchVariables, mv)
	}
	return matchVariables
}
func (mmc *mockMatchCondition) Operator() string      { return mmc.operator }
func (mmc *mockMatchCondition) NegateCondition() bool { return mmc.negateCondition }
func (mmc *mockMatchCondition) MatchValues() []string { return mmc.matchValues }
func (mmc *mockMatchCondition) Transforms() []string  { return mmc.transforms }

type mockMatchVariable struct {
	variableName string
	selector     string
}

func (mmv *mockMatchVariable) VariableName() string { return mmv.variableName }
func (mmv *mockMatchVariable) Selector() string     { return mmv.selector }

type mockConfigLogMetaData struct {
}

func (md *mockConfigLogMetaData) ResourceID() string { return "" }
func (md *mockConfigLogMetaData) InstanceID() string { return "" }

type mockIPReputationConfig struct {
	enabled bool
}

func (mirc *mockIPReputationConfig) Enabled() bool {
	return mirc.enabled
}
