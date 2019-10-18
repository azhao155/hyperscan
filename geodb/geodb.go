package geodb

import (
	"azwaf/ipaddresses"
	"azwaf/waf"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/btree"
	"github.com/rs/zerolog"
)

const geoIPDataCacheName = waf.Path + "geoipdatacache.json"

// NewGeoDB instantiates a new GeoIP database.
func NewGeoDB(logger zerolog.Logger, fs GeoIPFileSystem) waf.GeoDB {
	db := &geoDBImpl{tree: btree.New(2), logger: logger, fs: fs}

	// Load data from cache if available.
	if geoIPData, err := db.readDataFromCache(geoIPDataCacheName); err == nil {
		db.updateBTreeData(geoIPData)
	}

	return db
}

type geoDBImpl struct {
	tree   *btree.BTree
	logger zerolog.Logger
	fs     GeoIPFileSystem
}

func (db *geoDBImpl) PutGeoIPData(geoIPData []waf.GeoIPDataRecord) (err error) {
	// Sanity check on the data set.
	if err = db.validateGeoIPData(geoIPData); err != nil {
		db.logger.Err(err).Msg("Error while validating GeoIP data set")
		return
	}

	// Back up GeoIP data.
	if err = db.writeDataToCache(geoIPDataCacheName, geoIPData); err != nil {
		db.logger.Err(err).Msg("Error while writing GeoIP data set to cache")
	}

	db.updateBTreeData(geoIPData)
	return
}

func (db *geoDBImpl) GeoLookup(ipAddr string) (countryCode string) {
	ipNode := newGeoIPTreeNodeFromIPOctets(ipAddr)
	foundNode := db.tree.Get(ipNode)

	// The data set does not contain known reserved addresses.
	// Log the event if lookup returns a miss for non-reserved address
	// and return "" as country code.
	if foundNode == nil || len(foundNode.(geoIPTreeNode).CountryCode) != 2 {
		if special, _ := ipaddresses.IsSpecialPurposeAddress(ipAddr); !special {
			db.logger.Warn().Msgf("GeoDB failed to look up record for IP address %s", ipAddr)
		}
		return
	}

	countryCode = foundNode.(geoIPTreeNode).CountryCode
	return
}

func (db *geoDBImpl) updateBTreeData(geoIPData []waf.GeoIPDataRecord) {
	newTree := btree.New(2)
	for _, geoIPDataRecord := range geoIPData {
		node := newGeoIPTreeNodeFromGeoIPDataRecord(geoIPDataRecord)
		newTree.ReplaceOrInsert(node)
	}

	db.tree = newTree
}

func (db *geoDBImpl) writeDataToCache(filename string, geoIPData []waf.GeoIPDataRecord) (err error) {
	data := []*geoIPDataRecordImpl{}
	for _, rec := range geoIPData {
		data = append(data, &geoIPDataRecordImpl{
			StartIPVal:     rec.StartIP(),
			EndIPVal:       rec.EndIP(),
			CountryCodeVal: rec.CountryCode(),
		})
	}

	bytes, err := json.Marshal(data)

	if err != nil {
		return
	}

	if err = db.fs.WriteFile(filename, bytes); err != nil {
		return
	}

	return
}

func (db *geoDBImpl) readDataFromCache(filename string) (geoIPData []waf.GeoIPDataRecord, err error) {
	bytes, err := db.fs.ReadFile(filename)

	if err != nil {
		return
	}

	var data = []*geoIPDataRecordImpl{}

	if err = json.Unmarshal(bytes, &data); err != nil {
		return
	}

	for _, rec := range data {
		geoIPData = append(geoIPData, rec)
	}

	return
}

func (db *geoDBImpl) validateGeoIPData(geoIPData []waf.GeoIPDataRecord) (err error) {
	sort.Slice(geoIPData, func(i, j int) bool {
		return geoIPData[i].StartIP() < geoIPData[j].StartIP()
	})

	for i, curr := range geoIPData {
		if curr.StartIP() > curr.EndIP() {
			errFmt := "GeoIP data record (%s, %s, %s) has StartIP greater than EndIP"
			err = fmt.Errorf(errFmt, curr.StartIP(), curr.EndIP(), curr.CountryCode())
			return
		}

		if i == 0 {
			continue
		}

		prev := geoIPData[i-1]
		if curr.StartIP() <= prev.EndIP() {
			errFmt := "Overlap found between data records (%s, %s, %s) and (%s, %s, %s)"
			err = fmt.Errorf(errFmt, prev.StartIP(), prev.EndIP(), prev.CountryCode(), curr.StartIP(), curr.EndIP(), curr.CountryCode())
			return
		}
	}

	return
}

type geoIPTreeNode struct {
	StartIP     uint32
	EndIP       uint32
	CountryCode string
}

func (node geoIPTreeNode) Less(other btree.Item) bool {
	return node.StartIP < other.(geoIPTreeNode).StartIP && node.EndIP < other.(geoIPTreeNode).EndIP
}

func newGeoIPTreeNodeFromIPOctets(ipAddr string) geoIPTreeNode {
	ip, _ := ipaddresses.ParseIPAddress(ipAddr)
	return newGeoIPTreeNodeFromUInt32(ip)
}

func newGeoIPTreeNodeFromUInt32(ip uint32) geoIPTreeNode {
	return geoIPTreeNode{StartIP: ip, EndIP: ip}
}

func newGeoIPTreeNodeFromGeoIPDataRecord(rec waf.GeoIPDataRecord) geoIPTreeNode {
	// Safeguard for data cleanness.
	countryCode := strings.ToUpper(rec.CountryCode())
	countryCode = strings.TrimSpace(countryCode)

	return geoIPTreeNode{
		StartIP:     rec.StartIP(),
		EndIP:       rec.EndIP(),
		CountryCode: countryCode,
	}
}
