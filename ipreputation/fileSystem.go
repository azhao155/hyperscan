package ipreputation

import (
	"io/ioutil"
)

// FileSystem provides wrappers around ioutil.WriteFile and ioutil.ReadFile to support mocking
type FileSystem interface {
	WriteFile(string, []byte) error
	ReadFile(string) ([]byte, error)
}

// FileSystemImpl is the implementation for file system interface
type FileSystemImpl struct {
}

// WriteFile is a wrapper around ioutil.WriteFile to support mocking
func (fs *FileSystemImpl) WriteFile(fileName string, data []byte) error {
	return ioutil.WriteFile(fileName, data, 0644)
}

// ReadFile is a wrapper around ioutil.ReadFile to support mocking
func (fs *FileSystemImpl) ReadFile(fileName string) (data []byte, err error) {
	return ioutil.ReadFile(fileName)
}
