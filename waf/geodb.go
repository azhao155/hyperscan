package waf

// GeoDB is a data base that maps IPv4 addresses to their corresponding 2-letter country codes.
type GeoDB interface {
	PutGeoIPData(geoIPData []GeoIPDataRecord) (err error)
	GeoLookup(ipAddr string) (countryCode string)
}

// GeoIPDataRecord is the structured entries in the curated Interflow GeoIP data set.
type GeoIPDataRecord interface {
	StartIP() uint32
	EndIP() uint32
	CountryCode() string
}
