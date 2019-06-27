package waf

import (
	"io/ioutil"
	"os"
)

// ConfigFileSystem is the interface to handle config file create/open/remove/read
type ConfigFileSystem interface {
	RemoveFile(filename string) error
	WriteFile(filename string, data string) error
	ReadFile(filename string) (string, error)
	ReadDir(dirname string) ([]string, error)
}

// ConfigFileSystemImpl is the implementation for config file interface
type ConfigFileSystemImpl struct {
}

// ReadFile is to read file and return string context
func (fs *ConfigFileSystemImpl) ReadFile(name string) (string, error) {
	b, err := ioutil.ReadFile(name)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// WriteFile is to write string context into file
func (fs *ConfigFileSystemImpl) WriteFile(name string, json string) error {
	return ioutil.WriteFile(name, []byte(json), 0777)
}

// RemoveFile is the delete file from config file system
func (fs *ConfigFileSystemImpl) RemoveFile(name string) error {
	return os.Remove(name)
}

// ReadDir reads the config file system directory by dirname and returns a list of directory entries sorted by filename.
func (fs *ConfigFileSystemImpl) ReadDir(name string) ([]string, error) {
	names := make([]string, 0)

	files, err := ioutil.ReadDir(name)
	if err != nil {
		return names, err
	}

	for _, file := range files {
		names = append(names, file.Name())
	}

	return names, nil
}
