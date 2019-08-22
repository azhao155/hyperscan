package waf

import (
	"errors"
	"testing"
)

type mockSecRuleConfig struct{}

func (c *mockSecRuleConfig) Enabled() bool { return false }

func (c *mockSecRuleConfig) RuleSetID() string { return "OWASP CRS 3.0" }

type mockGeoDBConfig struct{}

func (c *mockGeoDBConfig) Enabled() bool { return true }

type mockPolicyConfig struct{}

func (c *mockPolicyConfig) ConfigID() string { return "waf policy 1" }

func (c *mockPolicyConfig) SecRuleConfig() SecRuleConfig { return &mockSecRuleConfig{} }

func (c *mockPolicyConfig) GeoDBConfig() GeoDBConfig { return &mockGeoDBConfig{} }

func (c *mockPolicyConfig) IPReputationConfig() IPReputationConfig { return nil }

type mockConfig struct{}

func (c *mockConfig) ConfigVersion() int32 { return 0 }

func (c *mockConfig) PolicyConfigs() []PolicyConfig {
	return []PolicyConfig{&mockPolicyConfig{}}
}

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
	if secRule.Enabled() != false {
		t.Fatalf("PutConfig SecRule has wrong Enabled field")
	}

	if secRule.RuleSetID() != "OWASP CRS 3.0" {
		t.Fatalf("PutConfig SecRule has wrong RuleSetID field")
	}

	geoDB := policyConfig[0].GeoDBConfig()
	if geoDB.Enabled() != true {
		t.Fatalf("PutConfig GeoDB has wrong Enabled field")
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
