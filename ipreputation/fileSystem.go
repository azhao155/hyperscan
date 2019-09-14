package ipreputation

import (
	"io/ioutil"
)

type fileSystem interface {
	writeFile(string, []byte) error
	readFile(string) ([]byte, error)
}

// FileSystemImpl is the implementation for file system interface
type FileSystemImpl struct {
}

func (fs *FileSystemImpl) writeFile(fileName string, data []byte) error {
	return ioutil.WriteFile(fileName, data, 0644)
}

func (fs *FileSystemImpl) readFile(fileName string) (data []byte, err error) {
	return ioutil.ReadFile(fileName)
}
