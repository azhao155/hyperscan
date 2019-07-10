package hyperscan

import (
	"crypto/sha1"
	"encoding/hex"
	hs "github.com/flier/gohs/hyperscan"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// DbCache is a cache for pre-built Hyperscan databases.
type DbCache interface {
	cacheID(patterns []*hs.Pattern) string
	loadFromCache(cacheID string) hs.BlockDatabase
	saveToCache(cacheID string, db hs.BlockDatabase)
}

type dbCacheImpl struct {
	fs CacheFilesystem
}

// NewDbCache creates a DbCache using the given file system interface.
func NewDbCache(fs CacheFilesystem) DbCache {
	return &dbCacheImpl{fs: fs}
}

func (c *dbCacheImpl) cacheID(patterns []*hs.Pattern) string {
	hash := sha1.New() // Keep a hash of the current DB that we will use as a cache ID.
	for _, p := range patterns {
		io.WriteString(hash, strconv.Itoa(p.Id))
		io.WriteString(hash, p.String())
		io.WriteString(hash, strconv.Itoa(int(p.Flags)))
	}

	return hex.EncodeToString(hash.Sum(nil))
}

func (c *dbCacheImpl) loadFromCache(cacheID string) hs.BlockDatabase {
	dir := c.fs.getCacheFileDirectory()

	if !c.fs.exists(dir) {
		return nil
	}

	bb, err := c.fs.readFile(filepath.Join(dir, cacheID))
	if err != nil {
		return nil
	}

	db, err := hs.UnmarshalBlockDatabase(bb)
	if err != nil {
		return nil
	}

	return db
}

func (c *dbCacheImpl) saveToCache(cacheID string, db hs.BlockDatabase) {
	dir := c.fs.getCacheFileDirectory()
	c.fs.createDirIfNotExist(dir)

	bb, err := db.Marshal()
	if err != nil {
		return
	}

	c.fs.writeFile(filepath.Join(dir, cacheID), bb, 0644)
}

// CacheFilesystem is an interface with the functionality the cache needs to persist to a filesystem.
type CacheFilesystem interface {
	readFile(filename string) ([]byte, error)
	writeFile(filename string, data []byte, perm os.FileMode) error
	createDirIfNotExist(dir string)
	getCacheFileDirectory() string
	exists(filename string) bool
}

type cacheFilesystemImpl struct{}

// NewCacheFileSystem creates a CacheFilesystem that uses the real file system.
func NewCacheFileSystem() CacheFilesystem {
	return &cacheFilesystemImpl{}
}

func (c *cacheFilesystemImpl) readFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

func (c *cacheFilesystemImpl) writeFile(filename string, data []byte, perm os.FileMode) error {
	return ioutil.WriteFile(filename, data, perm)
}

func (c *cacheFilesystemImpl) createDirIfNotExist(dir string) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			panic(err)
		}
	}
}

func (c *cacheFilesystemImpl) getCacheFileDirectory() string {
	execPath, _ := os.Executable()
	dir := filepath.Join(filepath.Dir(execPath), "hyperscancache")

	// Was this a tmp bin file started by "go run" or "dlv"?
	startedByDlv := strings.HasSuffix(execPath, "/debug")
	startedByGoRun := strings.Contains(strings.Replace(dir, "\\", "/", -1), "/go-build")
	if startedByDlv || startedByGoRun {
		// Instead use a directory under the source tree
		_, s, _, _ := runtime.Caller(0)
		s = filepath.Dir(s)
		dir = filepath.Join(s, "../hyperscancache")
	}

	return dir
}

func (c *cacheFilesystemImpl) exists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}
