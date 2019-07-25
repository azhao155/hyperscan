package integrationtesting

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGetTests(t *testing.T) {
	assert := assert.New(t)

	_, thissrcfilename, _, _ := runtime.Caller(0)
	d := filepath.Dir(thissrcfilename)
	tt, err := GetTests(d, "")
	assert.Nil(err)
	assert.Equal(3, len(tt))

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

	t2 := tt[2]
	expectedBody := `--------------------------1aa6ce6559102
content-disposition: form-data; name="a"

hello world 1
--------------------------1aa6ce6559102--`
	buf.Reset()
	r = t2.Requests[0].(*mockWafHTTPRequest)
	_, _ = buf.ReadFrom(r.BodyReader())
	assert.Equal(expectedBody, buf.String())
}
