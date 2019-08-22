package grpc

import (
	pb "azwaf/proto"
	"testing"
)

var wrapperTestConfig1 = pb.SecRuleConfig{
	Enabled:   false,
	RuleSetId: "abc",
}

var wrapperTestConfig2 = pb.GeoDBConfig{
	Enabled: true,
}

var policyConfig = pb.PolicyConfig{
	ConfigID:      "wafPolicy1",
	SecRuleConfig: &wrapperTestConfig1,
	GeoDBConfig:   &wrapperTestConfig2,
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

	geoDB := locConfig[0].GeoDBConfig()
	if geoDB.Enabled() != wrapperTestConfig2.Enabled {
		t.Fatalf("TestConfigsConversion GeoDB has wrong Enabled field")
	}
}
