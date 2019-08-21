package waf

// SecRuleConfig is SecRule Engine config
type SecRuleConfig interface {
	ID() string
	Enabled() bool
	RuleSetID() string
}

// CustomRuleConfig is CustomRule Engine config
type CustomRuleConfig interface {
}

// GeoDBConfig is GeoDB Engine config
type GeoDBConfig interface {
	ID() string
	Enabled() bool
}

// IPReputationConfig is IPReputation Engine config
type IPReputationConfig interface {
	ID() string
	Enabled() bool
}

// Config is the top level configuration object
type Config interface {
	SecRuleConfigs() []SecRuleConfig
	GeoDBConfigs() []GeoDBConfig
	IPReputationConfigs() []IPReputationConfig
}

// ConfigConverter convert Config to/from JSON string
type ConfigConverter interface {
	SerializeToJSON(Config) (string, error)
	DeserializeFromJSON(string) (Config, error)
}
