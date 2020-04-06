package grpc

import (
	pb "azwaf/proto"
	"testing"
)

var wrapperGlobalExclusion = pb.Exclusion{
	MatchVariable:         "RequestCookieNames",
	SelectorMatchOperator: "Contains",
	Selector:              "Hello",
}

var wrapperRuleExclusion = pb.Exclusion{
	MatchVariable:         "RequestArgNames",
	SelectorMatchOperator: "StartsWith",
	Selector:              "Rule",
	Rules:                 []int32{930120, 932160},
}

var wrapperTestConfig1 = pb.SecRuleConfig{
	Enabled:    false,
	RuleSetId:  "abc",
	Exclusions: []*pb.Exclusion{&wrapperGlobalExclusion, &wrapperRuleExclusion},
}

var testMatchVariable = pb.MatchVariable{
	VariableName: "RemoteAddr",
	Selector:     "",
}

var testMatchCondition = pb.MatchCondition{
	MatchVariables:  []*pb.MatchVariable{&testMatchVariable},
	Operator:        "GeoMatch",
	NegateCondition: false,
	MatchValues:     []string{"US", "IN", "CN"},
	Transforms:      []string{},
}

var testCustomRule = pb.CustomRule{
	Name:            "customRule1",
	Priority:        42,
	RuleType:        "MatchRule",
	MatchConditions: []*pb.MatchCondition{&testMatchCondition},
	Action:          "Block",
}

var policyConfig = pb.PolicyConfig{
	ConfigID:      "wafPolicy1",
	SecRuleConfig: &wrapperTestConfig1,
	CustomRuleConfig: &pb.CustomRuleConfig{
		CustomRules: []*pb.CustomRule{&testCustomRule},
	},
}

var wafConfigs = pb.WAFConfig{
	ConfigVersion: 1,
	PolicyConfigs: []*pb.PolicyConfig{&policyConfig},
}

func TestConfigsConversion(t *testing.T) {
	config1 := configPbWrapper{pb: &wafConfigs}
	cc := ConfigConverterImpl{}
	str, _ := cc.SerializeToJSON(&config1)

	config2, _ := cc.DeserializeFromJSON(str)

	locConfig := config2.PolicyConfigs()

	if len(locConfig) != 1 {
		t.Fatalf("TestConfigsConversion has wrong number of Location config")
	}

	secRule := locConfig[0].SecRuleConfig()
	if secRule.RuleSetID() != wrapperTestConfig1.RuleSetId {
		t.Fatalf("TestConfigsConversion SecRule has wrong id")
	}

	if secRule.Enabled() != wrapperTestConfig1.Enabled {
		t.Fatalf("TestConfigsConversion SecRule has wrong Enabled field")
	}

	// Testing Global Exclusions
	excl := secRule.Exclusions()
	if excl == nil {
		t.Fatalf(" TestConfigsConversion SecRule Exclusion is not present")
	}

	if excl[0].Selector() != wrapperGlobalExclusion.Selector || excl[0].SelectorMatchOperator() != wrapperGlobalExclusion.SelectorMatchOperator || excl[0].MatchVariable() != wrapperGlobalExclusion.MatchVariable || excl[0].Rules() != nil {
		t.Fatalf(" TestConfigsConversion SecRule Incorrect Exclusions. Actual {%s,%s,%s,%v} Expected {RequestArgsNames,StartsWith,Hello, nil}", excl[0].MatchVariable(), excl[0].SelectorMatchOperator(), excl[0].Selector(), excl[0].Rules())
	}

	// Test Rule Exclusions
	if excl[1].Selector() != wrapperRuleExclusion.Selector || excl[1].SelectorMatchOperator() != wrapperRuleExclusion.SelectorMatchOperator || excl[1].MatchVariable() != wrapperRuleExclusion.MatchVariable || excl[1].Rules() == nil {
		t.Fatalf(" TestConfigsConversion SecRule Incorrect Exclusions. Actual {%s,%s,%s,%v} Expected {RequestArgsNames,StartsWith,Rule, %v}", excl[1].MatchVariable(), excl[1].SelectorMatchOperator(), excl[1].Selector(), excl[1].Rules(), wrapperRuleExclusion.Rules)
	}

	if excl[1].Rules()[0] != 930120 || excl[1].Rules()[1] != 932160 {
		t.Fatalf(" TestconfigsConversion SecRule Incorrect Rules in Exclusions. Actual {%v} Expected {%v}", excl[1].Rules(), wrapperRuleExclusion.Rules)
	}

	// Test CustomRules converstion
	locCustomRules := locConfig[0].CustomRuleConfig().CustomRules()
	if len(locCustomRules) != len(policyConfig.CustomRuleConfig.CustomRules) {
		t.Fatalf("TestConfigConvertion CustomRules has wrong CustomRule count")
	}

	if len(locCustomRules) == 0 {
		return
	}

	locCustomRule := locCustomRules[0]
	if locCustomRule.Name() != testCustomRule.Name {
		t.Fatalf("TestConfigConvertion CustomRule has wrong Name")
	}

	if locCustomRule.Priority() != int(testCustomRule.Priority) {
		t.Fatalf("TestConfigConvertion CustomRule has wrong Priority")
	}

	if locCustomRule.RuleType() != testCustomRule.RuleType {
		t.Fatalf("TestConfigConvertion CustomRule has wrong RuleType")
	}

	if locCustomRule.Action() != testCustomRule.Action {
		t.Fatalf("TestConfigConvertion CustomRule has wrong Action")
	}

	locMatchConditions := locCustomRule.MatchConditions()
	if len(locMatchConditions) != len(testCustomRule.MatchConditions) {
		t.Fatalf("TestConfigConvertion CustomRule has wrong MatchCondition count")
	}

	if len(locMatchConditions) == 0 {
		return
	}

	locMatchCondition := locMatchConditions[0]
	if locMatchCondition.Operator() != testMatchCondition.Operator {
		t.Fatalf("TestConfigConvertion MatchCondition has wrong Operator")
	}

	if locMatchCondition.NegateCondition() != testMatchCondition.NegateCondition {
		t.Fatalf("TestConfigConvertion MatchCondition has wrong NegateCondition")
	}

	locMatchVariables := locMatchCondition.MatchVariables()
	if len(locMatchVariables) != len(testMatchCondition.MatchVariables) {
		t.Fatalf("TestConfigConvertion MatchCondition has wrong MatchVariable count")
	}

	if len(locMatchVariables) > 0 {
		locMatchVariable := locMatchVariables[0]
		if locMatchVariable.VariableName() != testMatchVariable.VariableName {
			t.Fatalf("TestConfigConvertion MatchVariable has wrong VariableName")
		}
		if locMatchVariable.Selector() != testMatchVariable.Selector {
			t.Fatalf("TestConfigConvertion MatchVariable has wrong Selector")
		}
	}

	locMatchValues := locMatchCondition.MatchValues()
	if len(locMatchValues) != len(testMatchCondition.MatchValues) {
		t.Fatalf("TestConfigConvertion MatchVariable has wrong MatchValue count")
	}

	if len(locMatchValues) > 0 && locMatchValues[0] != testMatchCondition.MatchValues[0] {
		t.Fatalf("TestConfigConvertion MatchVariable has wrong MatchValue")
	}

	locTransforms := locMatchCondition.Transforms()
	if len(locTransforms) != len(testMatchCondition.Transforms) {
		t.Fatalf("TestConfigConvertion MatchVariable has wrong Transform count")
	}

	if len(locTransforms) > 0 && locTransforms[0] != testMatchCondition.Transforms[0] {
		t.Fatalf("TestConfigConvertion MatchVariable has wrong Transform")
	}
}

func TestConfigsConversionMissingJsonString(t *testing.T) {
	converter := &ConfigConverterImpl{}

	json := `{"configVersion":1}`
	c, e := converter.DeserializeFromJSON(json)

	if e != nil {
		t.Fatalf("Fail to convert the string which is missing fields")
	}

	if len(c.PolicyConfigs()) != 0 {
		t.Fatalf("Policy configs field is missing, but still contain policy config")
	}

	if c.LogMetaData() != nil {
		t.Fatalf("LogMetaData is missing, but still not nil")
	}
}
