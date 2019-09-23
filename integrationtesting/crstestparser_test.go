package integrationtesting

import (
	"azwaf/waf"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	yaml "gopkg.in/yaml.v3"
	"github.com/stretchr/testify/assert"
)

// TestCase for CRS regression test
type TestCase struct {
	TestTitle string
	Requests  []waf.HTTPRequest
	// Expected Output
	MatchExpected  bool
	ExpectedRuleID int
}

// YAML parsing requires exporting of struct fields
type input struct {
	DestAddr string            `yaml:"dest_addr"`
	Method   string            `yaml:"method"`
	Port     string            `yaml:"port"`
	URI      string            `yaml:"uri"`
	Version  string            `yaml:"version"`
	Headers  map[string]string `yaml:"headers"`
	Data     interface{}       `yaml:"data"`
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
			req := &mockWafHTTPRequest{uri: "http://localhost" + input.URI, method: input.Method, body: body}

			hasContentType := false
			for k, v := range s.Stage.Input.Headers {
				req.headers = append(req.headers, &mockHeaderPair{k: k, v: v})
				if strings.EqualFold("content-type", k) {
					hasContentType = true
				}
			}

			// Default content type
			if len(body) > 0 && !hasContentType {
				req.headers = append(req.headers, &mockHeaderPair{k: "Content-Type", v: "application/x-www-form-urlencoded"})
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


