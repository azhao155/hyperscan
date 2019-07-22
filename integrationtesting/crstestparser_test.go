package integrationtesting

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestGetTests(t *testing.T) {
	assert := assert.New(t)

	d, err := os.Getwd()
	if err != nil {
		t.Fatalf("Error getting working dir %v", err)
		return
	}

	tt, err := GetTests(d, "")
	assert.Nil(err)
	assert.Equal(2, len(tt))

	t0 := tt[0]
	assert.Equal(1, len(t0.Requests))

	r := t0.Requests[0].(*mockWafHTTPRequest)
	h := r.Headers()[0].(*mockHeaderPair)
	assert.Equal("User-Agent", h.Key())
	assert.Equal("ModSecurity CRS 3 Tests", h.Value())

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r.BodyReader())
	assert.Equal("test=value", buf.String())

	assert.Equal("911100-1", t0.TestTitle)
	assert.True(t0.MatchExpected)
	assert.Equal(911100, t0.ExpectedRuleID)

	secondTestCase := tt[1]
	assert.Equal(1, len(secondTestCase.Requests))
	assert.Equal("911100-2", secondTestCase.TestTitle)
	assert.False(secondTestCase.MatchExpected)
	assert.Equal(911100, secondTestCase.ExpectedRuleID)
}
