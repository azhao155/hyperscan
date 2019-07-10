package waf

import (
	"fmt"
	"strconv"
	"sync"
)

// Path is the config file directory path
const Path = ""

// ConfigMgr is the top level configuration management interface to AzWaf.
type ConfigMgr interface {
	PutConfig(c Config) (int64, error)
	DisposeConfig(int) error
}

type configMgrImpl struct {
	curVersion int64
	fileSystem ConfigFileSystem
	converter  ConfigConverter
	mux        sync.Mutex
}

// NewConfigMgr create a configuration manager instance.
func NewConfigMgr(fileSystem ConfigFileSystem, converter ConfigConverter) (ConfigMgr, map[int64]Config, error) {
	c := &configMgrImpl{}

	c.fileSystem = fileSystem
	c.converter = converter

	m, err := c.restoreConfig()
	if err != nil {
		return nil, nil, err
	}

	return c, m, nil
}

// PutConfig writes the config protobuf into disk.
func (c *configMgrImpl) PutConfig(config Config) (int64, error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	str, err := c.converter.SerializeToJSON(config)
	if err != nil {
		return -1, err
	}

	err = c.fileSystem.WriteFile(Path+strconv.FormatInt(c.curVersion, 10), str)
	if err != nil {
		return -1, err
	}

	c.curVersion++
	return c.curVersion - 1, nil
}

func (c *configMgrImpl) DisposeConfig(version int) error {
	c.mux.Lock()
	defer c.mux.Unlock()

	err := c.fileSystem.RemoveFile(Path + strconv.Itoa(version))

	if err != nil {
		return fmt.Errorf("Delete file: %v has error: %v", version, err)
	}

	return nil
}

func (c *configMgrImpl) restoreConfig() (map[int64]Config, error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	c.curVersion = 0
	m := make(map[int64]Config)
	files, err := c.fileSystem.ReadDir(Path)
	if err != nil {
		return m, err
	}

	for _, f := range files {
		str, err := c.fileSystem.ReadFile(Path + f)
		if err != nil {
			return m, fmt.Errorf("Read config file version  %v has error: %v", f, err)
		}

		wafConfig, err := c.converter.DeserializeFromJSON(str)
		if err != nil {
			return m, fmt.Errorf("Decode config file version  %v has error: %v", f, err)
		}

		v, err := strconv.ParseInt(f, 10, 64)
		if err != nil {
			return m, fmt.Errorf("Processing file %v has error: %v", f, err)
		}

		c.curVersion = max(c.curVersion, v)
		m[v] = wafConfig
	}

	return m, nil
}

func max(x, y int64) int64 {
	if x < y {
		return y
	}
	return x
}
