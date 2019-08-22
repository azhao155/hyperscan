package waf

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// Path is the config file directory path
const Path = "/appgwroot/config/azwaf/"

const prefix = "AzWAFConfig"

// ConfigMgr is the top level configuration management interface to AzWaf.
type ConfigMgr interface {
	PutConfig(c Config) error
	DisposeConfig(int) ([]string, error)
}

type configMgrImpl struct {
	fileSystem  ConfigFileSystem
	converter   ConfigConverter
	mux         sync.Mutex
	configIDMap map[int][]string
}

// NewConfigMgr create a configuration manager instance.
func NewConfigMgr(fileSystem ConfigFileSystem, converter ConfigConverter) (ConfigMgr, map[int]Config, error) {
	c := &configMgrImpl{}

	c.fileSystem = fileSystem
	c.converter = converter
	c.configIDMap = make(map[int][]string)

	err := c.fileSystem.MkDir(Path)
	if err != nil {
		return nil, nil, err
	}

	m, err := c.restoreConfig()
	if err != nil {
		return nil, nil, err
	}

	return c, m, nil
}

// PutConfig writes the config protobuf into disk.
func (c *configMgrImpl) PutConfig(config Config) error {
	c.mux.Lock()
	defer c.mux.Unlock()

	str, err := c.converter.SerializeToJSON(config)
	if err != nil {
		return err
	}

	version := int(config.ConfigVersion())

	err = c.fileSystem.WriteFile(Path+prefix+strconv.Itoa(version), str)
	if err != nil {
		return err
	}

	c.configIDMap[version] = make([]string, 0)

	for _, config := range config.PolicyConfigs() {
		c.configIDMap[version] = append(c.configIDMap[version], config.ConfigID())
	}

	return nil
}

func (c *configMgrImpl) DisposeConfig(version int) ([]string, error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	ids, ok := c.configIDMap[version]

	if !ok {
		return nil, fmt.Errorf("Version %v not existing, can't dispose", version)
	}

	delete(c.configIDMap, version)

	err := c.fileSystem.RemoveFile(Path + prefix + strconv.Itoa(version))

	if err != nil {
		return nil, fmt.Errorf("Delete file: %v has error: %v", version, err)
	}

	return ids, nil
}

func (c *configMgrImpl) restoreConfig() (map[int]Config, error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	m := make(map[int]Config)
	files, err := c.fileSystem.ReadDir(Path)
	if err != nil {
		return m, err
	}

	for _, f := range files {
		if !strings.HasPrefix(f, prefix) {
			continue
		}

		str, err := c.fileSystem.ReadFile(Path + f)
		if err != nil {
			return m, fmt.Errorf("Read config file version  %v has error: %v", f, err)
		}

		wafConfig, err := c.converter.DeserializeFromJSON(str)
		if err != nil {
			return m, fmt.Errorf("Decode config file version  %v has error: %v", f, err)
		}

		v, err := strconv.Atoi(f[len(prefix):])
		if err != nil {
			return m, fmt.Errorf("Processing file %v has error: %v", f, err)
		}

		m[v] = wafConfig

		c.configIDMap[v] = make([]string, 0)

		for _, config := range wafConfig.PolicyConfigs() {
			c.configIDMap[v] = append(c.configIDMap[v], config.ConfigID())
		}
	}

	return m, nil
}
