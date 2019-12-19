package hyperscan

import (
	"os"
	"testing"

	hs "github.com/flier/gohs/hyperscan"
)

func TestDbCacheLoadSave(t *testing.T) {
	// Arrange
	patterns := []*hs.Pattern{}
	p := hs.NewPattern("abc+", 0)
	p.Id = 100
	p.Flags = hs.SingleMatch | hs.PrefilterMode
	patterns = append(patterns, p)
	db, err := hs.NewBlockDatabase(patterns...)
	if err != nil {
		t.Fatalf("got unexpected error: %s", err)
	}
	fs := newMockCacheFilesystem()
	cache := NewDbCache(fs)

	// Act
	cacheID := cache.cacheID(patterns)
	cache.saveToCache(cacheID, db)
	db2 := cache.loadFromCache(cacheID)

	// Assert
	scratch, err := hs.NewScratch(db2)
	if err != nil {
		t.Fatalf("failed to create Hyperscan scratch space: %v", err)
	}

	found := false
	handler := func(id uint, from, to uint64, flags uint, context interface{}) error {
		if id == 100 {
			found = true
		}
		return nil
	}
	err = db2.Scan([]byte("abcccc"), scratch, handler, nil)
	if err != nil {
		t.Fatalf("got unexpected error: %s", err)
	}

	if !found {
		t.Fatalf("loaded Hyperscan DB did not work")
	}

	db.Close()
	db2.Close()
}

type mockCacheFilesystem struct {
	fs map[string][]byte
}

func newMockCacheFilesystem() CacheFilesystem {
	return &mockCacheFilesystem{fs: make(map[string][]byte)}
}
func (c *mockCacheFilesystem) readFile(filename string) ([]byte, error) { return c.fs[filename], nil }
func (c *mockCacheFilesystem) writeFile(filename string, data []byte, perm os.FileMode) error {
	c.fs[filename] = data
	return nil
}
func (c *mockCacheFilesystem) createDirIfNotExist(dir string) {}
func (c *mockCacheFilesystem) getCacheFileDirectory() string  { return "/mycachedir" }
func (c *mockCacheFilesystem) exists(filename string) bool    { return true }
