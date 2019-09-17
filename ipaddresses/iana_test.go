package ipaddresses

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSpecialPurposeAddress(t *testing.T) {
	assert := assert.New(t)

	ipAddr := "132.239.180.101"
	special, err := IsSpecialPurposeAddress(ipAddr)
	assert.False(special)
	assert.Nil(err)

	ipAddr = "192.168.0.1"
	special, err = IsSpecialPurposeAddress(ipAddr)
	assert.True(special)
	assert.Nil(err)
}
