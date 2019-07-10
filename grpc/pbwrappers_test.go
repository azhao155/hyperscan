package grpc

import (
	pb "azwaf/proto"
	"testing"
)

var wrapperTestConfig1 = pb.SecRuleConfig{
	Id:      "SecRuleConfig123",
	Enabled: false,
}

var wrapperTestConfig2 = pb.GeoDBConfig{
	Id:      "GeoDbConfig345",
	Enabled: true,
}

var wafConfigs = pb.WAFConfig{
	SecRuleConfigs: []*pb.SecRuleConfig{&wrapperTestConfig1},
	GeoDBConfigs:   []*pb.GeoDBConfig{&wrapperTestConfig2},
}

func TestConfigsConversion(t *testing.T) {
	config1 := configPbWrapper{pb: &wafConfigs}
	cc := ConfigConverterImpl{}
	str, _ := cc.SerializeToJSON(&config1)

	config2, _ := cc.DeserializeFromJSON(str)

	secRules := config2.SecRuleConfigs()

	if len(secRules) != 1 {
		t.Fatalf("TestConfigsConversion has wrong number of SecRule config")
	}

	if secRules[0].ID() != wrapperTestConfig1.Id {
		t.Fatalf("TestConfigsConversion SecRule has wrong id")
	}

	if secRules[0].Enabled() != wrapperTestConfig1.Enabled {
		t.Fatalf("TestConfigsConversion SecRule has wrong Enabled field")
	}

	geoDBs := config2.GeoDBConfigs()

	if len(geoDBs) != 1 {
		t.Fatalf("TestConfigsConversion has wrong number of GeoDB config")
	}

	if geoDBs[0].ID() != wrapperTestConfig2.Id {
		t.Fatalf("TestConfigsConversion GeoDB has wrong id")
	}

	if geoDBs[0].Enabled() != wrapperTestConfig2.Enabled {
		t.Fatalf("TestConfigsConversion GeoDB has wrong Enabled field")
	}
}
