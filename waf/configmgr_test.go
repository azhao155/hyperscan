package waf

import (
	"errors"
	"testing"
)

type mockExclusion struct {
	matchVariable         string
	selectorMatchOperator string
	selector              string
	rules                 []int32
}

func (r *mockExclusion) MatchVariable() string         { return r.matchVariable }
func (r *mockExclusion) SelectorMatchOperator() string { return r.selectorMatchOperator }
func (r *mockExclusion) Selector() string              { return r.selector }
func (r *mockExclusion) Rules() []int32                { return r.rules }

type mockSecRuleConfig struct {
	ruleEx map[Exclusion][]int
}

func (c *mockSecRuleConfig) Enabled() bool     { return true }
func (c *mockSecRuleConfig) RuleSetID() string { return "OWASP CRS 3.0" }
func (c *mockSecRuleConfig) Exclusions() []Exclusion {
	return []Exclusion{
		&mockExclusion{
			selectorMatchOperator: "StartsWith",
			selector:              "arg1",
			matchVariable:         "RequestArgNames",
			rules:                 []int32{950950, 950951},
		},
		&mockExclusion{
			selectorMatchOperator: "Contains",
			selector:              "globalArg",
			matchVariable:         "RequestCookieNames",
		},
	}
}

type mockCustomRule struct{}

func (mcr *mockCustomRule) Name() string                      { return "" }
func (mcr *mockCustomRule) Priority() int                     { return 0 }
func (mcr *mockCustomRule) RuleType() string                  { return "" }
func (mcr *mockCustomRule) MatchConditions() []MatchCondition { return []MatchCondition{} }
func (mcr *mockCustomRule) Action() string                    { return "" }

type mockCustomRuleConfig struct{}

func (c *mockCustomRuleConfig) CustomRules() []CustomRule { return []CustomRule{&mockCustomRule{}} }

type mockPolicyConfig struct {
	isDetectionMode  bool
	isShadowMode     bool
	requestBodyCheck bool
}

type mockIPReputationConfig struct{}

func (c *mockIPReputationConfig) Enabled() bool { return true }

func (c *mockPolicyConfig) ConfigID() string                       { return "waf policy 1" }
func (c *mockPolicyConfig) IsDetectionMode() bool                  { return c.isDetectionMode }
func (c *mockPolicyConfig) IsShadowMode() bool                     { return c.isShadowMode }
func (c *mockPolicyConfig) RequestBodyCheck() bool                 { return c.requestBodyCheck }
func (c *mockPolicyConfig) SecRuleConfig() SecRuleConfig           { return &mockSecRuleConfig{} }
func (c *mockPolicyConfig) CustomRuleConfig() CustomRuleConfig     { return &mockCustomRuleConfig{} }
func (c *mockPolicyConfig) IPReputationConfig() IPReputationConfig { return &mockIPReputationConfig{} }

type mockConfigLogMetaData struct {
}

func (h *mockConfigLogMetaData) ResourceID() string { return "appgwWaf" }
func (h *mockConfigLogMetaData) InstanceID() string { return "vm1" }

type mockConfig struct {
	mpc mockPolicyConfig
}

func (c *mockConfig) ConfigVersion() int32 { return 0 }
func (c *mockConfig) PolicyConfigs() []PolicyConfig {
	return []PolicyConfig{&c.mpc}
}

func (c *mockConfig) LogMetaData() ConfigLogMetaData { return &mockConfigLogMetaData{} }

type mockConfigConverter struct{}

func (c *mockConfigConverter) SerializeToJSON(Config) (string, error) {
	return "random", nil
}
func (c *mockConfigConverter) DeserializeFromJSON(str string) (Config, error) {
	if str == "random" {
		return &mockConfig{}, nil
	}

	return nil, nil
}

type mockFileSystem struct {
	Files map[string]string
}

func (fs *mockFileSystem) ReadFile(name string) (string, error) {
	if val, ok := fs.Files[name]; ok {
		return val, nil
	}

	return "", errors.New("can't find version")
}

func (fs *mockFileSystem) WriteFile(name string, json string) error {
	fs.Files[name] = json

	return nil
}

func (fs *mockFileSystem) RemoveFile(name string) error {
	delete(fs.Files, name)

	return nil
}

func (fs *mockFileSystem) ReadDir(name string) ([]string, error) {
	names := make([]string, 0)

	for k := range fs.Files {
		names = append(names, k[len(Path):])
	}

	return names, nil
}

func (fs *mockFileSystem) MkDir(name string) error {
	return nil
}

func TestPutConfig(t *testing.T) {
	ms := &mockFileSystem{}
	ms.Files = make(map[string]string)

	cc := &mockConfigConverter{}

	c, _, _ := NewConfigMgr(ms, cc)
	config := mockConfig{}
	c.PutConfig(&config)

	c, m, _ := NewConfigMgr(ms, cc)

	if len(m) != 1 {
		t.Fatalf("PutConfig restore wrong config")
	}

	policyConfig := m[0].PolicyConfigs()

	if len(policyConfig) != 1 {
		t.Fatalf("PutConfig has wrong number of SecRule config")
	}

	if policyConfig[0].ConfigID() != "waf policy 1" {
		t.Fatalf("PutConfig PolicyConfig has wrong id")
	}

	secRule := policyConfig[0].SecRuleConfig()
	if secRule.Enabled() != true {
		t.Fatalf("PutConfig SecRule has wrong Enabled field")
	}

	if secRule.RuleSetID() != "OWASP CRS 3.0" {
		t.Fatalf("PutConfig SecRule has wrong RuleSetID field")
	}

	if len(secRule.Exclusions()) != 2 {
		t.Fatalf("PutConfig SecRule does not have the expected number of exclusions.")
	}

	if secRule.Exclusions()[0].SelectorMatchOperator() != "StartsWith" || secRule.Exclusions()[0].Selector() != "arg1" || secRule.Exclusions()[0].MatchVariable() != "RequestArgNames" || secRule.Exclusions()[1].SelectorMatchOperator() != "Contains" || secRule.Exclusions()[1].Selector() != "globalArg" || secRule.Exclusions()[1].MatchVariable() != "RequestCookieNames" {
		t.Fatalf("PutConfig SecRule does not have the expected exclusion ")
	}

	if len(secRule.Exclusions()[0].Rules()) != 2 || secRule.Exclusions()[0].Rules()[0] != 950950 || secRule.Exclusions()[0].Rules()[1] != 950951 || len(secRule.Exclusions()[1].Rules()) != 0 {
		t.Fatalf("PutConfig SecRule does not have the expected exclusion ")
	}
}

func TestDisposeConfig(t *testing.T) {
	ms := &mockFileSystem{}
	ms.Files = make(map[string]string)

	cc := &mockConfigConverter{}

	c, _, _ := NewConfigMgr(ms, cc)
	config := mockConfig{}
	c.PutConfig(&config)
	s, _ := c.DisposeConfig(0)

	if len(s) != 1 {
		t.Fatalf("DisposeConfig return wrong number of config")
	}

	if s[0] != "waf policy 1" {
		t.Fatalf("DisposeConfig return wrong config")
	}

	c, m, _ := NewConfigMgr(ms, cc)
	if len(m) != 0 {
		t.Fatalf("DisposeConfig return wrong number of config")
	}
}
