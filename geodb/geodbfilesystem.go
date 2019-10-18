package geodb

import (
	"io/ioutil"

	"github.com/rs/zerolog"
)

type geoIPDataRecordImpl struct {
	StartIPVal     uint32 `json:"StartIP"`
	EndIPVal       uint32 `json:"EndIP"`
	CountryCodeVal string `json:"CountryCode"`
}

func (rec *geoIPDataRecordImpl) StartIP() uint32 {
	return rec.StartIPVal
}

func (rec *geoIPDataRecordImpl) EndIP() uint32 {
	return rec.EndIPVal
}

func (rec *geoIPDataRecordImpl) CountryCode() string {
	return rec.CountryCodeVal
}

// NewGeoIPFileSystem creates a new file system for handling GeoIP data set I/O
func NewGeoIPFileSystem(logger zerolog.Logger) GeoIPFileSystem {
	return &fileSystemImpl{logger: logger}
}

// GeoIPFileSystem is the interface to handle GeoIP data file create/open/remove/read
type GeoIPFileSystem interface {
	WriteFile(filename string, buf []byte) error
	ReadFile(filename string) ([]byte, error)
}

type fileSystemImpl struct {
	logger zerolog.Logger
}

// ReadFile is to read the cache file and return JSON encoding of the GeoIP data
func (fs *fileSystemImpl) ReadFile(name string) (buf []byte, err error) {
	buf, err = ioutil.ReadFile(name)
	return
}

// WriteFile is to persist the JSON encoding of the GeoIP data on disk
func (fs *fileSystemImpl) WriteFile(name string, buf []byte) (err error) {
	err = ioutil.WriteFile(name, buf, 0644)
	return
}
