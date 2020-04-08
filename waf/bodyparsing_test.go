package waf

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockHeaderPair struct {
	k string
	v string
}

func (h *mockHeaderPair) Key() string   { return h.k }
func (h *mockHeaderPair) Value() string { return h.v }

func TestMediaTypeStructsInSync(t *testing.T) {
	if int(_lastReqBodyTypes) != len(ReqBodyTypeStrings) {
		t.Fatalf("int(_lastReqBodyTypes) != len(ReqBodyTypeStrings)")
	}
}

func TestGetLengthAndTypeFromHeaders(t *testing.T) {
	assert := assert.New(t)
	bodyContent := string(make([]byte, 128*1024))
	req := &mockWafHTTPRequest{
		configID:   "abc",
		remoteAddr: "255.255.255.255",
		uri:        "/",
		headers: []HeaderPair{
			&mockHeaderPair{
				k: "Content-Length",
				v: fmt.Sprint(len(bodyContent)),
			},
		},
		body: bodyContent,
	}
	contentLength, reqBodyType, multipartBoundary, err := getLengthAndTypeFromHeaders(req)
	assert.Equal(128*1024, contentLength)
	assert.Equal(OtherBody, reqBodyType)
	assert.Equal("", multipartBoundary)
	assert.Nil(err)
}
