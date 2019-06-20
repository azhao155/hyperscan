package libinjection

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIsSQLi(t *testing.T) {
	assert := assert.New(t)

	input := "--1 UNION ALL SELECT * FROM FOO"
	found, fingerprint := IsSQLi(input)
	assert.True(found, "SQLI attack not detected")
	var expected = "1UEok"
	assert.Equal(expected, fingerprint, "Fingerprints do not match")

	input = `foo 'bar'`
	found, fingerprint = IsSQLi(input)
	assert.False(found, "SQLI attack should not be detected")
}

func TestIsXSS(t *testing.T) {
	input := "<script>"
	found := IsXSS(input)
	assert.True(t, found, "XSS attack not detected")

	input = "script"
	found = IsXSS(input)
	assert.False(t, found, "XSS attack should not be detected")
}
