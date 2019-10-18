package geodb

import (
	"azwaf/ipaddresses"
	"azwaf/testutils"
	"azwaf/waf"
	"encoding/json"
	"testing"

	"github.com/google/btree"
	"github.com/stretchr/testify/assert"
)

type mockGeoIPDataRecord struct {
	mockStartIP     uint32
	mockEndIP       uint32
	mockCountryCode string
}

func (m *mockGeoIPDataRecord) StartIP() uint32     { return m.mockStartIP }
func (m *mockGeoIPDataRecord) EndIP() uint32       { return m.mockEndIP }
func (m *mockGeoIPDataRecord) CountryCode() string { return m.mockCountryCode }

// A sample from real Geo IP data set.
var testGeoIPData = []waf.GeoIPDataRecord{
	&mockGeoIPDataRecord{mockStartIP: 1491692113, mockEndIP: 1491692113, mockCountryCode: "TR"},
	&mockGeoIPDataRecord{mockStartIP: 1823934982, mockEndIP: 1823934982, mockCountryCode: "US"},
	&mockGeoIPDataRecord{mockStartIP: 1878097675, mockEndIP: 1878097719, mockCountryCode: "TW"},
	&mockGeoIPDataRecord{mockStartIP: 3144112629, mockEndIP: 3144112629, mockCountryCode: "BR"},
}

var referenceGeoIPData = []waf.GeoIPDataRecord{
	&geoIPDataRecordImpl{StartIPVal: 1491692113, EndIPVal: 1491692113, CountryCodeVal: "TR"},
	&geoIPDataRecordImpl{StartIPVal: 1823934982, EndIPVal: 1823934982, CountryCodeVal: "US"},
	&geoIPDataRecordImpl{StartIPVal: 1878097675, EndIPVal: 1878097719, CountryCodeVal: "TW"},
	&geoIPDataRecordImpl{StartIPVal: 3144112629, EndIPVal: 3144112629, CountryCodeVal: "BR"},
}

// JSON encoding of the above data.
var testGeoIPDataEncoded, _ = json.Marshal(referenceGeoIPData)

var mockFSFiles = map[string][]byte{
	geoIPDataCacheName: testGeoIPDataEncoded,
}

type mockGeoDBFileSystem struct{}

func (mfs *mockGeoDBFileSystem) ReadFile(filename string) (buf []byte, err error) {
	if data, ok := mockFSFiles[filename]; ok {
		return data, nil
	}
	return
}

func (mfs *mockGeoDBFileSystem) WriteFile(filename string, buf []byte) error {
	mockFSFiles[filename] = buf
	return nil
}

func TestNewGeoDB(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	logger := testutils.NewTestLogger(t)
	mfs := &mockGeoDBFileSystem{}

	// Act
	db := NewGeoDB(logger, mfs)

	// Assert
	assert.NotNil(db.(*geoDBImpl).tree)
}

func TestPutGeoIPData(t *testing.T) {
	assert := assert.New(t)
	mfs := &mockGeoDBFileSystem{}

	// Arrange
	db := &geoDBImpl{fs: mfs}

	// Act
	err := db.PutGeoIPData(testGeoIPData)

	// Assert
	assert.Nil(err)
	assert.NotNil(db.tree)
	for _, rec := range testGeoIPData {
		node := newGeoIPTreeNodeFromGeoIPDataRecord(rec)
		assert.True(db.tree.Has(node))
	}
}

func TestGeoDBGeoLookup(t *testing.T) {
	assert := assert.New(t)
	db := &geoDBImpl{}
	tree := btree.New(2)

	for _, rec := range testGeoIPData {
		tree.ReplaceOrInsert(geoIPTreeNode{
			StartIP:     rec.StartIP(),
			EndIP:       rec.EndIP(),
			CountryCode: rec.CountryCode(),
		})
	}
	db.tree = tree

	// Node being tested: "StartIP: 1878097675, EndIP: 1878097719, CountryCode: TW".
	leftEdgeIP := "111.241.127.11"
	leftEdgeCountryCode := db.GeoLookup(leftEdgeIP)
	assert.Equal(leftEdgeCountryCode, "TW")

	midPointIP := "111.241.127.33"
	midPointCountryCode := db.GeoLookup(midPointIP)
	assert.Equal(midPointCountryCode, "TW")

	rightEdgeIP := "111.241.127.55"
	rightEdgeCountryCode := db.GeoLookup(rightEdgeIP)
	assert.Equal(rightEdgeCountryCode, "TW")

	reservedIP := "0.0.0.0"
	reservedCountryCode := db.GeoLookup(reservedIP)
	assert.Zero(reservedCountryCode)

	noMatchIP := "8.8.8.8"
	noMatchCountryCode := db.GeoLookup(noMatchIP)
	assert.Zero(noMatchCountryCode)
}

func TestGeoDBGeoLookupWithOverlap(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	db := &geoDBImpl{}
	tree := btree.New(2)
	geoIPData := []waf.GeoIPDataRecord{
		&mockGeoIPDataRecord{mockStartIP: 0x00000000, mockEndIP: 0x3fffffff, mockCountryCode: "03"},
		&mockGeoIPDataRecord{mockStartIP: 0x40000000, mockEndIP: 0x7fffffff, mockCountryCode: "47"},
		&mockGeoIPDataRecord{mockStartIP: 0x80000000, mockEndIP: 0xbfffffff, mockCountryCode: "8b"},
		&mockGeoIPDataRecord{mockStartIP: 0xc0000000, mockEndIP: 0xffffffff, mockCountryCode: "cf"},
		&mockGeoIPDataRecord{mockStartIP: 0xbabeface, mockEndIP: 0xdeadbeef, mockCountryCode: "bd"},
	}

	for _, rec := range geoIPData {
		tree.ReplaceOrInsert(geoIPTreeNode{
			StartIP:     rec.StartIP(),
			EndIP:       rec.EndIP(),
			CountryCode: rec.CountryCode(),
		})
	}
	db.tree = tree

	// Act
	testIP := ipaddresses.ToOctets(0xcafebabe)
	result := db.GeoLookup(testIP)

	// Assert
	assert.Contains([]string{"bd", "cf"}, result)
}

func TestGeoDBUpdateBTreeData(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	db := &geoDBImpl{}

	// Act
	db.updateBTreeData(testGeoIPData)

	// Assert
	for _, rec := range testGeoIPData {
		node := newGeoIPTreeNodeFromGeoIPDataRecord(rec)
		assert.True(db.tree.Has(node))
	}
}

func TestWriteDataToCache(t *testing.T) {
	assert := assert.New(t)

	db := &geoDBImpl{}
	db.fs = &mockGeoDBFileSystem{}

	testFilename := "TestWriteDataToCache"
	db.writeDataToCache(testFilename, testGeoIPData)

	assert.Equal(testGeoIPDataEncoded, mockFSFiles[testFilename])
}

func TestReadDataFromCache(t *testing.T) {
	assert := assert.New(t)
	db := &geoDBImpl{}
	db.fs = &mockGeoDBFileSystem{}

	testFilename := "TestReadDataFromCache"
	mockFSFiles[testFilename] = testGeoIPDataEncoded

	data, err := db.readDataFromCache(testFilename)

	assert.Nil(err)
	assert.Equal(referenceGeoIPData, data)
}

func TestNewGeoIPTreeNodeFromIPOctets(t *testing.T) {
	assert := assert.New(t)

	ipAddr := "192.168.0.1"
	ip := uint32(0xc0a80001)

	node := newGeoIPTreeNodeFromIPOctets(ipAddr)

	assert.Equal(node.StartIP, ip)
	assert.Equal(node.EndIP, ip)
	assert.Equal(node.CountryCode, "")
}

func TestNewGeoIPTreeNodeFromUInt32(t *testing.T) {
	assert := assert.New(t)

	var ip uint32 = 12
	node := newGeoIPTreeNodeFromUInt32(ip)

	assert.Equal(node.StartIP, ip)
	assert.Equal(node.EndIP, ip)
}

func TestNewGeoIPTreeNodeFromGeoIPDataRecord(t *testing.T) {
	assert := assert.New(t)

	geoIPDataRecord := &geoIPDataRecordImpl{StartIPVal: 0x01234567, EndIPVal: 0x89abcdef, CountryCodeVal: "GO"}
	node := newGeoIPTreeNodeFromGeoIPDataRecord(geoIPDataRecord)

	assert.Equal(node.StartIP, uint32(0x01234567))
	assert.Equal(node.EndIP, uint32(0x89abcdef))
	assert.Equal(node.CountryCode, "GO")
}

func TestGeoIPTreeNodeLessThan(t *testing.T) {
	assert := assert.New(t)

	lowRange := geoIPTreeNode{StartIP: 0x00112233, EndIP: 0x44556677}
	lowIP := newGeoIPTreeNodeFromUInt32(lowRange.StartIP)
	highRange := geoIPTreeNode{StartIP: 0x8899aabb, EndIP: 0xccddeeff}

	assert.True(lowRange.Less(highRange))
	assert.True(lowIP.Less(highRange))
	assert.False(lowIP.Less(lowRange))
	assert.False(lowRange.Less(lowIP))
}

func TestValidateGeoIPDataNoError(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	db := &geoDBImpl{}
	geoIPData := []waf.GeoIPDataRecord{
		&mockGeoIPDataRecord{mockStartIP: 0xc0000000, mockEndIP: 0xffffffff, mockCountryCode: "cf"},
		&mockGeoIPDataRecord{mockStartIP: 0x80000000, mockEndIP: 0xbfffffff, mockCountryCode: "8b"},
		&mockGeoIPDataRecord{mockStartIP: 0x40000000, mockEndIP: 0x7fffffff, mockCountryCode: "47"},
		&mockGeoIPDataRecord{mockStartIP: 0x00000000, mockEndIP: 0x3fffffff, mockCountryCode: "03"},
	}

	// Act
	err := db.validateGeoIPData(geoIPData)

	// Assert
	assert.Nil(err)
}

func TestValidateGeoIPDataInvalidRecords(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	db := &geoDBImpl{}
	geoIPData := []waf.GeoIPDataRecord{
		&mockGeoIPDataRecord{mockStartIP: 0xffffffff, mockEndIP: 0xc0000000, mockCountryCode: "fc"},
		&mockGeoIPDataRecord{mockStartIP: 0xbfffffff, mockEndIP: 0x80000000, mockCountryCode: "b8"},
		&mockGeoIPDataRecord{mockStartIP: 0x7fffffff, mockEndIP: 0x40000000, mockCountryCode: "74"},
		&mockGeoIPDataRecord{mockStartIP: 0x3fffffff, mockEndIP: 0x00000000, mockCountryCode: "30"},
	}

	// Act
	err := db.validateGeoIPData(geoIPData)

	// Assert
	assert.Error(err)
}

func TestValidateGeoIPDataOverlaps(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	db := &geoDBImpl{}
	geoIPData := []waf.GeoIPDataRecord{
		&mockGeoIPDataRecord{mockStartIP: 0x00000000, mockEndIP: 0x3fffffff, mockCountryCode: "03"},
		&mockGeoIPDataRecord{mockStartIP: 0x40000000, mockEndIP: 0x7fffffff, mockCountryCode: "47"},
		&mockGeoIPDataRecord{mockStartIP: 0x80000000, mockEndIP: 0xbfffffff, mockCountryCode: "8b"},
		&mockGeoIPDataRecord{mockStartIP: 0xc0000000, mockEndIP: 0xffffffff, mockCountryCode: "cf"},
		&mockGeoIPDataRecord{mockStartIP: 0xbabeface, mockEndIP: 0xdeadbeef, mockCountryCode: "no"},
	}

	// Act
	err := db.validateGeoIPData(geoIPData)

	// Assert
	assert.Error(err)
}
