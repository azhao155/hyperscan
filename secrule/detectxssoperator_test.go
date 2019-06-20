package secrule

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDetectXSSOperator(t *testing.T) {
	assert := assert.New(t)
	dxo := &detectXSSOperator{}
	found, output, err := dxo.eval("<script>", "")
	assert.Nil(err)
	assert.True(found, "XSS not detected")
	var expected = ""
	assert.Equal(expected, output)
}
