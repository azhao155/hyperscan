package waf

// SecRuleConfig is SecRule Engine config
type SecRuleConfig interface {
	Enabled() bool
	RuleSetID() string
}

// CustomRuleConfig is CustomRule Engine config
type CustomRuleConfig interface {
}

// GeoDBConfig is GeoDB Engine config
type GeoDBConfig interface {
	Enabled() bool
}

// IPReputationConfig is IPReputation Engine config
type IPReputationConfig interface {
	Enabled() bool
}

// PolicyConfig is config defined for each location
type PolicyConfig interface {
	ConfigID() string
	SecRuleConfig() SecRuleConfig
	GeoDBConfig() GeoDBConfig
	IPReputationConfig() IPReputationConfig
}

// Config is the top level configuration object
type Config interface {
	ConfigVersion() int32
	PolicyConfigs() []PolicyConfig
}

// ConfigConverter convert Config to/from JSON string
type ConfigConverter interface {
	SerializeToJSON(Config) (string, error)
	DeserializeFromJSON(string) (Config, error)
}
