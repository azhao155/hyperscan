package integrationtesting

import (
	"azwaf/waf"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const bodyParsingConfigID = "abc"

func formatMultipartString(s string) string {
	return strings.Replace(strings.Replace(s, "\r", "", -1), "\n", "\r\n", -1)
}

func newBodyParsingConfig() waf.Config {
	config := &mockWAFConfig{
		configVersion: 0,
		policyConfigs: []waf.PolicyConfig{
			&mockPolicyConfig{
				configID:                 bodyParsingConfigID,
				requestBodyCheck:         true,
				requestBodySizeLimitInKb: 128,
				fileUploadSizeLimitInMb:  1,
			},
		},
		logMetaData: &mockConfigLogMetaData{},
	}
	return config
}

func TestPutRequestBodySizeLimitConfig(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	wafServer := newTestAzwafServer(t)

	// Act
	config := newBodyParsingConfig()
	err := wafServer.PutConfig(config)

	// Assert
	assert.Nil(err)
}

func TestEvalRequestBodySizeLimit(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	bodyContentOverLimit := "[" + strings.Repeat(`"a",`, (128*1024)/4) + `"a"]`
	assert.True(len(bodyContentOverLimit) >= 128*1024)
	overLimitReq := &mockWafHTTPRequest{
		configID:   bodyParsingConfigID,
		remoteAddr: "255.255.255.255",
		uri:        "/",
		headers: []waf.HeaderPair{
			&mockHeaderPair{
				k: "Content-Length",
				v: fmt.Sprint(len(bodyContentOverLimit)),
			},
			&mockHeaderPair{
				k: "Content-Type",
				v: "application/json",
			},
		},
		body: bodyContentOverLimit,
	}

	bodyContentUnderLimit := "[" + strings.Repeat(`"a",`, (127*1024)/4) + `"a"]`
	assert.True(len(bodyContentUnderLimit) < 128*1024)
	underLimitReq := &mockWafHTTPRequest{
		configID:   bodyParsingConfigID,
		remoteAddr: "255.255.255.255",
		uri:        "/",
		headers: []waf.HeaderPair{
			&mockHeaderPair{
				k: "Content-Length",
				v: fmt.Sprint(len(bodyContentUnderLimit)),
			},
			&mockHeaderPair{
				k: "Content-Type",
				v: "application/json",
			},
		},
		body: bodyContentUnderLimit,
	}

	wafServer := newTestAzwafServer(t)
	config := newBodyParsingConfig()
	wafServer.PutConfig(config)

	// Act
	blockDecision, err := wafServer.EvalRequest(overLimitReq)
	assert.Nil(err)
	passDecision, err := wafServer.EvalRequest(underLimitReq)
	assert.Nil(err)

	// Assert
	assert.Equal(waf.Block, blockDecision)
	assert.Equal(waf.Pass, passDecision)
}

func TestEvalRequestFileUploadSizeLimit(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	bodyContentOverLimit := formatMultipartString(fmt.Sprintf(`------WebKitFormBoundaryG7cKLhr0svnwZky0
Content-Disposition: form-data; name="file1"; filename="zeros.txt"

%v	

------WebKitFormBoundaryG7cKLhr0svnwZky0--
`, strings.Repeat("0", 1024*1024)))
	assert.True(len(bodyContentOverLimit) >= 1024*1024)
	overLimitReq := &mockWafHTTPRequest{
		configID:   bodyParsingConfigID,
		remoteAddr: "255.255.255.255",
		uri:        "/",
		headers: []waf.HeaderPair{
			&mockHeaderPair{
				k: "Content-Length",
				v: fmt.Sprint(len(bodyContentOverLimit)),
			},
			&mockHeaderPair{
				k: "Content-Type",
				v: "multipart/form-data; boundary=----WebKitFormBoundaryG7cKLhr0svnwZky0",
			},
		},
		body: bodyContentOverLimit,
	}

	bodyContentUnderLimit := formatMultipartString(fmt.Sprintf(`------WebKitFormBoundaryG7cKLhr0svnwZky0
Content-Disposition: form-data; name="file1"; filename="zeros.txt"

%v	

------WebKitFormBoundaryG7cKLhr0svnwZky0--
`, strings.Repeat("0", 1023*1024))) 
	assert.True(len(bodyContentUnderLimit) < 1024*1024)
	underLimitReq := &mockWafHTTPRequest{
		configID:   bodyParsingConfigID,
		remoteAddr: "255.255.255.255",
		uri:        "/",
		headers: []waf.HeaderPair{
			&mockHeaderPair{
				k: "Content-Length",
				v: fmt.Sprint(len(bodyContentUnderLimit)),
			},
			&mockHeaderPair{
				k: "Content-Type",
				v: "multipart/form-data; boundary=----WebKitFormBoundaryG7cKLhr0svnwZky0",
			},
		},
		body: bodyContentUnderLimit,
	}

	wafServer := newTestAzwafServer(t)
	config := newBodyParsingConfig()
	wafServer.PutConfig(config)

	fmt.Println(len(bodyContentOverLimit))
	fmt.Println(len(bodyContentUnderLimit))

	// Act
	blockDecision, err := wafServer.EvalRequest(overLimitReq)
	assert.Nil(err)
	passDecision, err := wafServer.EvalRequest(underLimitReq)
	assert.Nil(err)

	// Assert
	assert.Equal(waf.Block, blockDecision)
	assert.Equal(waf.Pass, passDecision)
}

func TestEvalRequestFileUploadSizeLimitBadContentLengthHeader(t *testing.T) {
	assert := assert.New(t)

	// Arrange
	bodyContentOverLimit := formatMultipartString(fmt.Sprintf(`------WebKitFormBoundaryG7cKLhr0svnwZky0
Content-Disposition: form-data; name="file1"; filename="zeros.txt"

%v	

------WebKitFormBoundaryG7cKLhr0svnwZky0--
`, strings.Repeat("0", 1024*1024)))
	assert.True(len(bodyContentOverLimit) >= 1024*1024)
	overLimitReq := &mockWafHTTPRequest{
		configID:   bodyParsingConfigID,
		remoteAddr: "255.255.255.255",
		uri:        "/",
		headers: []waf.HeaderPair{
			&mockHeaderPair{
				k: "Content-Length",
				v: "0",
			},
			&mockHeaderPair{
				k: "Content-Type",
				v: "multipart/form-data; boundary=----WebKitFormBoundaryG7cKLhr0svnwZky0",
			},
		},
		body: bodyContentOverLimit,
	}

	bodyContentUnderLimit := formatMultipartString(fmt.Sprintf(`------WebKitFormBoundaryG7cKLhr0svnwZky0
Content-Disposition: form-data; name="file1"; filename="zeros.txt"

%v	

------WebKitFormBoundaryG7cKLhr0svnwZky0--
`, strings.Repeat("0", 1023*1024)))
	assert.True(len(bodyContentUnderLimit) < 1024*1024)
	underLimitReq := &mockWafHTTPRequest{
		configID:   bodyParsingConfigID,
		remoteAddr: "255.255.255.255",
		uri:        "/",
		headers: []waf.HeaderPair{
			&mockHeaderPair{
				k: "Content-Length",
				v: "0",
			},
			&mockHeaderPair{
				k: "Content-Type",
				v: "multipart/form-data; boundary=----WebKitFormBoundaryG7cKLhr0svnwZky0",
			},
		},
		body: bodyContentUnderLimit,
	}

	fmt.Println(len(bodyContentUnderLimit))

	wafServer := newTestAzwafServer(t)
	config := newBodyParsingConfig()
	wafServer.PutConfig(config)

	// Act
	blockDecision, err := wafServer.EvalRequest(overLimitReq)
	assert.Nil(err)
	passDecision, err := wafServer.EvalRequest(underLimitReq)
	assert.Nil(err)

	// Assert
	assert.Equal(waf.Block, blockDecision)
	assert.Equal(waf.Pass, passDecision)
}
