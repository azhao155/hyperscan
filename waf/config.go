package waf

// SecRuleConfig is SecRule Engine config
type SecRuleConfig interface {
	Enabled() bool
	RuleSetID() string
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
	CustomRuleConfig() CustomRuleConfig
	IPReputationConfig() IPReputationConfig
}

// ConfigLogMetaData is log meta data inside config
type ConfigLogMetaData interface {
	ResourceID() string
	InstanceID() string
}

// Config is the top level configuration object
type Config interface {
	ConfigVersion() int32
	PolicyConfigs() []PolicyConfig
	LogMetaData() ConfigLogMetaData
}

// ConfigConverter convert Config to/from JSON string
type ConfigConverter interface {
	SerializeToJSON(Config) (string, error)
	DeserializeFromJSON(string) (Config, error)
}
