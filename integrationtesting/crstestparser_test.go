package integrationtesting

import (
	"azwaf/encoding"
	"azwaf/waf"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

// TestCase for CRS regression test
type TestCase struct {
	TestTitle string
	Requests  []waf.HTTPRequest
	// Expected Output
	MatchExpected  bool
	ExpectedRuleID int
	Skip           bool
}

// YAML parsing requires exporting of struct fields
type input struct {
	DestAddr       string            `yaml:"dest_addr"`
	Method         string            `yaml:"method"`
	Port           string            `yaml:"port"`
	URI            string            `yaml:"uri"`
	Version        string            `yaml:"version"`
	Headers        map[string]string `yaml:"headers"`
	Data           interface{}       `yaml:"data"`
	StopMagic      bool              `yaml:"stop_magic"`
	EncodedRequest string            `yaml:"encoded_request"`
}

type stage struct {
	Input  input             `yaml:"input"`
	Output map[string]string `yaml:"output"`
}

type stageWrapper struct {
	Stage stage `yaml:"stage"`
}

type test struct {
	TestTitle string         `yaml:"test_title"`
	Stages    []stageWrapper `yaml:"stages"`
}

type testFile struct {
	Meta  map[string]string `yaml:"meta"`
	Tests []test            `yaml:"tests"`
}

var ruleIDRegex = regexp.MustCompile(`(\d+)`)

// GetTests returns parsed tests from CRS YAML test files
func GetTests(testRootDir string, ruleID string) (tests []TestCase, err error) {
	var files []string
	err = filepath.Walk(testRootDir, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() && strings.HasSuffix(path, ruleID+".yaml") && !strings.HasSuffix(path, "test.yaml") {
			files = append(files, path)
		}
		return nil
	})

	if err != nil {
		return
	}

	if len(files) == 0 {
		err = fmt.Errorf("No test files found under %v folder", testRootDir)
		return
	}

	sort.Strings(files)

	for _, file := range files {
		testFile := parseTestFile(file)
		var tt []TestCase
		if tt, err = toTestCase(testFile); err != nil {
			return
		}
		tests = append(tests, tt...)
	}

	return
}

func parseTestFile(path string) (tf testFile) {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		log.Printf("%v", err)
	}

	yaml.Unmarshal(file, &tf)
	return
}

func toTestCase(file testFile) (testCases []TestCase, err error) {
	for _, t := range file.Tests {
		var tc TestCase
		tc.TestTitle = t.TestTitle

		for _, s := range t.Stages {
			input := s.Stage.Input

			body := getBody(input.Data)
			req := &mockWafHTTPRequest{uri: input.URI, method: input.Method, body: body}

			if input.EncodedRequest != "" {
				req, body, err = parseEncodedRequest(input.EncodedRequest)
				if err != nil {
					return
				}
			}

			if req.method == "" {
				req.method = "GET"
			}

			hasHost := false
			var contentType string
			hasContentLength := false
			for k, v := range s.Stage.Input.Headers {
				req.headers = append(req.headers, &mockHeaderPair{k: k, v: v})

				if k == "Content-Type" { // This is deliberately case sensitive, because it is case sensitive in FTW as well.
					contentType = v
				}

				if strings.EqualFold("content-length", k) {
					hasContentLength = true
				}

				if strings.EqualFold("host", k) {
					hasHost = true
				}
			}

			req.protocol = input.Version

			if !input.StopMagic {
				// Default content type
				if len(body) > 0 && contentType == "" {
					contentType = "application/x-www-form-urlencoded"
					req.headers = append(req.headers, &mockHeaderPair{k: "Content-Type", v: contentType})
				}

				// Percent encode bodies if the content type was "application/x-www-form-urlencoded" and not already percent-encoded.
				// This is a bit strange, but FTW does something like this.
				if contentType == "application/x-www-form-urlencoded" {
					if strings.ContainsAny(body, "%") {
						// Let's just assume the body was already percent encoded...
					} else {
						vals := make(url.Values)

						d := encoding.NewURLDecoder(bytes.NewBufferString(body))
						var k, v string
						for {
							k, v, err = d.Next()
							if err != nil {
								if err == io.EOF {
									err = nil
									break
								}
								return
							}

							vals[k] = append(vals[k], v)
						}

						body = vals.Encode()
						req.body = body
					}
				}

				// Default content length
				if len(body) > 0 && !hasContentLength {
					req.headers = append(req.headers, &mockHeaderPair{k: "Content-Length", v: strconv.Itoa(len(body))})
				}

				if req.protocol == "" {
					req.protocol = "HTTP/1.1"
				}

				// Default host if HTTP/1.1 (HTTP/1.0 does not require host)
				if req.protocol == "HTTP/1.1" && !hasHost {
					req.headers = append(req.headers, &mockHeaderPair{k: "Host", v: "localhost"})
				}
			}

			tc.Requests = append(tc.Requests, req)

			// Output processing
			tc.MatchExpected = false
			keys := []string{"log_contains", "no_log_contains"}
			for _, k := range keys {
				if v, ok := s.Stage.Output[k]; ok {
					if k == "log_contains" {
						tc.MatchExpected = true
					}

					if tc.ExpectedRuleID, err = strconv.Atoi(ruleIDRegex.FindString(v)); err != nil {
						return
					}
				}
			}
		}

		if enabled, ok := file.Meta["enabled"]; ok {
			if strings.EqualFold("false", strings.TrimSpace(enabled)) {
				tc.Skip = true
			}
		}

		testCases = append(testCases, tc)
	}

	return
}

// The data field in the YAML files can be either a single string, or a list of lines. This function returns a string from either.
func getBody(inputData interface{}) (body string) {
	switch d := inputData.(type) {
	case string:
		body = d
	case []interface{}:
		for _, line := range d {
			if line, ok := line.(string); ok {
				body = body + line + "\n"
			}
		}
		body = strings.Trim(body, "\n")
	}
	return
}

func parseEncodedRequest(encodedRequest string) (req *mockWafHTTPRequest, body string, err error) {
	req = &mockWafHTTPRequest{}

	var r []byte
	r, err = base64.StdEncoding.DecodeString(encodedRequest)
	if err != nil {
		return
	}

	buf := bytes.NewBuffer(r)
	var reqLine string
	reqLine, err = buf.ReadString('\n')
	if err != nil {
		return
	}

	reqLine = strings.TrimSpace(reqLine)
	reqLineSplit := strings.Split(reqLine, " ")
	if len(reqLineSplit) != 3 {
		err = fmt.Errorf("bad request line in encoded_request")
		return
	}

	req.method = reqLineSplit[0]
	req.uri = reqLineSplit[1]
	req.protocol = reqLineSplit[2]

	for {
		var headerLine string
		headerLine, err = buf.ReadString('\n')
		if err != nil {
			return
		}

		headerLine = strings.TrimSpace(headerLine)
		if headerLine == "" {
			break
		}

		headerLineSplit := strings.Split(headerLine, ":")
		if len(headerLineSplit) != 2 {
			err = fmt.Errorf("invalid header line in encoded_request")
			return
		}

		k := strings.TrimSpace(headerLineSplit[0])
		v := strings.TrimSpace(headerLineSplit[1])
		req.headers = append(req.headers, &mockHeaderPair{k: k, v: v})
	}

	req.body = buf.String()

	return
}

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
