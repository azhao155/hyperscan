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
	DisposeConfig(int) error
}

type configMgrImpl struct {
	curVersion int
	fileSystem ConfigFileSystem
	converter  ConfigConverter
	mux        sync.Mutex
}

// NewConfigMgr create a configuration manager instance.
func NewConfigMgr(fileSystem ConfigFileSystem, converter ConfigConverter) (ConfigMgr, map[int]Config, error) {
	c := &configMgrImpl{}

	c.fileSystem = fileSystem
	c.converter = converter

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

	err = c.fileSystem.WriteFile(Path+prefix+strconv.Itoa(c.curVersion), str)
	if err != nil {
		return err
	}

	c.curVersion++
	return nil
}

func (c *configMgrImpl) DisposeConfig(version int) error {
	c.mux.Lock()
	defer c.mux.Unlock()

	err := c.fileSystem.RemoveFile(Path + prefix + strconv.Itoa(version))

	if err != nil {
		return fmt.Errorf("Delete file: %v has error: %v", version, err)
	}

	return nil
}

func (c *configMgrImpl) restoreConfig() (map[int]Config, error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	c.curVersion = 0
	m := make(map[int]Config)
	files, err := c.fileSystem.ReadDir(Path)
	if err != nil {
		return m, err
	}

	var found = false
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

		found = true
		c.curVersion = max(c.curVersion, v)
		m[v] = wafConfig
	}

	if found {
		c.curVersion++
	}

	return m, nil
}

func max(x, y int) int {
	if x < y {
		return y
	}
	return x
}
