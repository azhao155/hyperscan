package secrule

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDetectSQLiOperator(t *testing.T) {
	assert := assert.New(t)
	dso := &detectSQLiOperator{}
	found, output, err := dso.eval("--1 UNION ALL SELECT * FROM FOO", "")
	assert.Nil(err)
	assert.True(found, "SQLI not detected")
	var expected = "1UEok"
	assert.Equal(expected, output, "Fingerprints do not match")
}
