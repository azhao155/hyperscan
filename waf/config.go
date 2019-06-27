package waf

// SecRuleConfig is SecRule Engine config
type SecRuleConfig interface {
	ID() string
	Enabled() bool
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
