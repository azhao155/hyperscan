package logging

import (
	"os"
)

// LogFile is the interface to handle log file append
type LogFile interface {
	Append(content []byte) (err error)
}

// LogFileSystem is the interface to handle log file directory creation and file open/append
type LogFileSystem interface {
	MkDir(dirname string) error
	Open(name string) (f LogFile, err error)
}

// LogFileImpl is the implementation for log file
type LogFileImpl struct {
	f *os.File
}

// Append will append the text(bytes) after if file is opened, otherwise it will do nothing
func (fs *LogFileImpl) Append(content []byte) (err error) {
	_, err = fs.f.Write(content)
	return
}

// LogFileSystemImpl is the implementation for log file interface
type LogFileSystemImpl struct {
}

// MkDir creates a directory named path, along with any necessary parents, and returns nil, or else returns an error. If path is already a directory, MkdirAll does nothing and returns nil.
func (fs *LogFileSystemImpl) MkDir(name string) error {
	return os.MkdirAll(name, 0777)
}

// Open get the file handle of the file based on the file path, will create the file if file not exist.
func (fs *LogFileSystemImpl) Open(name string) (ff LogFile, err error) {
	var f *os.File
	f, err = os.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	ff = &LogFileImpl{
		f: f,
	}
	return
}
