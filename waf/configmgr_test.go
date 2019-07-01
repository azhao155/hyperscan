package waf

import (
	"errors"
	"testing"
)

type mockSecRuleConfig struct{}

func (c *mockSecRuleConfig) ID() string { return "SecRuleConfig1" }

func (c *mockSecRuleConfig) Enabled() bool { return false }

type mockGeoDBConfig struct{}

func (c *mockGeoDBConfig) ID() string { return "GeoDbConfig1" }

func (c *mockGeoDBConfig) Enabled() bool { return true }

type mockConfig struct{}

func (c *mockConfig) SecRuleConfigs() []SecRuleConfig { return []SecRuleConfig{&mockSecRuleConfig{}} }

func (c *mockConfig) GeoDBConfigs() []GeoDBConfig { return []GeoDBConfig{&mockGeoDBConfig{}} }

func (c *mockConfig) IPReputationConfigs() []IPReputationConfig { return []IPReputationConfig{} }

type mockConfigConverter struct{}

func (c *mockConfigConverter) SerializeToJSON(Config) (string, error) {
	return "random", nil
}

func (c *mockConfigConverter) DeSerializeFromJSON(str string) (Config, error) {
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

	secRules := m[0].SecRuleConfigs()

	if len(secRules) != 1 {
		t.Fatalf("PutConfig has wrong number of SecRule config")
	}

	if secRules[0].ID() != "SecRuleConfig1" {
		t.Fatalf("PutConfig SecRule has wrong id")
	}

	if secRules[0].Enabled() != false {
		t.Fatalf("PutConfig SecRule has wrong Enabled field")
	}

	geoDBs := m[0].GeoDBConfigs()

	if len(geoDBs) != 1 {
		t.Fatalf("PutConfig has wrong number of GeoDB config")
	}

	if geoDBs[0].ID() != "GeoDbConfig1" {
		t.Fatalf("PutConfig GeoDB has wrong id")
	}

	if geoDBs[0].Enabled() != true {
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
	c.DisposeConfig(0)

	c, m, _ := NewConfigMgr(ms, cc)
	if len(m) != 0 {
		t.Fatalf("PutConfig restore wrong config")
	}
}
