package ipaddresses

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseIPAddressGood(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	ipAddr := "192.168.0.1"
	ipRef := uint32(3232235521)

	// Act
	ipConverted, err := ParseIPAddress(ipAddr)

	// Assert
	assert.Nil(err)
	assert.Equal(ipRef, ipConverted)
}

func TestParseIPAddressCIDR(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	ipAddrBad := "10.0.0.0/8"

	// Act
	_, err := ParseIPAddress(ipAddrBad)

	// Assert
	assert.Error(err)
}

func TestParseIPAddressInvalidOctets(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	ipAddrBad := "256.256.256.256"

	// Act
	_, err := ParseIPAddress(ipAddrBad)

	// Assert
	assert.Error(err)
}

func TestParseIPAddressExtraOctet(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	ipAddrBad := "0.0.0.0.0"

	// Act
	_, err := ParseIPAddress(ipAddrBad)

	// Assert
	assert.Error(err)
}

func TestParseIPAddressNonNumericOctets(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	ipAddrBad := "O.O.O.O"

	// Act
	_, err := ParseIPAddress(ipAddrBad)

	// Assert
	assert.Error(err)
}

// We are being strict about notation here.
// Disallowing "192.168.1" to be resolved as "192.168.0.1".
func TestParseIPAddressAbbreviated(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	ipAddrBad := "192.168.1"

	// Act
	_, err := ParseIPAddress(ipAddrBad)

	// Assert
	assert.Error(err)
}

func TestParseCIDRGood(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	cidr := "10.0.0.0/8"
	prefixRef := uint32(0x0a000000)
	maskRef := uint32(0xff000000)

	// Act
	prefix, mask, err := ParseCIDR(cidr)

	// Assert
	assert.Equal(prefix, prefixRef)
	assert.Equal(mask, maskRef)
	assert.Nil(err)
}

func TestParseCIDRNoSlash(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	cidrBad := "10.0.0.0"

	// Act
	_, _, err := ParseCIDR(cidrBad)

	// Assert
	assert.Error(err)
}

func TestParseCIDRExtraSlash(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	cidrBad := "10.0.0.0/16/8"

	// Act
	_, _, err := ParseCIDR(cidrBad)

	// Assert
	assert.Error(err)
}

func TestParseCIDRSlashTooLarge(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	cidrBad := "10.0.0.0/42"

	// Act
	_, _, err := ParseCIDR(cidrBad)

	// Assert
	assert.Error(err)
}

func TestParseCIDRNonNumericSlash(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	cidrBad := "10.0.0.0/eight"

	// Act
	_, _, err := ParseCIDR(cidrBad)

	// Assert
	assert.Error(err)
}

// Again, we are being strict about notation here.
// Disallowing "10/8".
func TestParseCIDRAbbreviation(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	cidrBad := "10/8"

	// Act
	_, _, err := ParseCIDR(cidrBad)

	// Assert
	assert.Error(err)
}

func TestInAddressSpacePositive(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	ipAddr := "192.168.0.1"
	cidr := "192.168.0.0/16"

	// Act
	result, err := InAddressSpace(ipAddr, cidr)

	// Assert
	assert.True(result)
	assert.Nil(err)
}

func TestInAddressSpaceNegative(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	ipAddr := "192.168.0.0"
	cidr := "192.168.128.0/17"

	// Act
	result, err := InAddressSpace(ipAddr, cidr)
	assert.False(result)

	// Assert
	assert.Nil(err)
}

func TestToOctets(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	ip := uint32(0x01020304)

	// Act
	ipAddr := ToOctets(ip)

	// Assert
	assert.Equal("1.2.3.4", ipAddr)
}
