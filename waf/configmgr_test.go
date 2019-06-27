package waf

import (
	pb "azwaf/proto"
	"errors"
	"testing"
)

var testConfig1 = pb.SecRuleConfig{
	Id:      "SecRuleConfig1",
	Enabled: false,
}

var testConfig2 = pb.GeoDBConfig{
	Id:      "GeoDbConfig1",
	Enabled: true,
}

var pbConfigs = pb.WAFConfig{
	SecRuleConfigs: []*pb.SecRuleConfig{&testConfig1},
	GeoDBConfigs:   []*pb.GeoDBConfig{&testConfig2},
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
	c, _, _ := NewConfigMgr(ms)
	config := configPbWrapper{pb: &pbConfigs}
	c.PutConfig(&config)

	c, m, _ := NewConfigMgr(ms)

	if len(m) != 1 {
		t.Fatalf("PutConfig restore wrong config")
	}

	secRules := m[0].SecRuleConfigs()

	if len(secRules) != 1 {
		t.Fatalf("PutConfig has wrong number of SecRule config")
	}

	if secRules[0].ID() != testConfig1.Id {
		t.Fatalf("PutConfig SecRule has wrong id")
	}

	if secRules[0].Enabled() != testConfig1.Enabled {
		t.Fatalf("PutConfig SecRule has wrong Enabled field")
	}

	geoDBs := m[0].GeoDBConfigs()

	if len(geoDBs) != 1 {
		t.Fatalf("PutConfig has wrong number of GeoDB config")
	}

	if geoDBs[0].ID() != testConfig2.Id {
		t.Fatalf("PutConfig GeoDB has wrong id")
	}

	if geoDBs[0].Enabled() != testConfig2.Enabled {
		t.Fatalf("PutConfig GeoDB has wrong Enabled field")
	}
}

func TestDisposeConfig(t *testing.T) {
	ms := &mockFileSystem{}
	ms.Files = make(map[string]string)
	c, _, _ := NewConfigMgr(ms)
	config := configPbWrapper{pb: &pbConfigs}
	c.PutConfig(&config)
	c.DisposeConfig(0)

	c, m, _ := NewConfigMgr(ms)
	if len(m) != 0 {
		t.Fatalf("PutConfig restore wrong config")
	}
}
