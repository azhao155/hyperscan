package bodyparsing

import (
	"azwaf/testutils"
	"azwaf/waf"
	"bytes"
	"io"
	"strings"
	"testing"
)

func arrangeAndRunBodyParser(t *testing.T, body io.Reader, fieldCb waf.ParsedBodyFieldCb, reqBodyType waf.ReqBodyType, multipartBoundary string) (err error) {
	rbp := NewRequestBodyParser(waf.DefaultLengthLimits)
	logger := testutils.NewTestLogger(t)
	err = rbp.Parse(logger, body, fieldCb, reqBodyType, 0, multipartBoundary, false)
	return
}

type parsedBodyFieldCbCall struct {
	contentType waf.FieldContentType
	fieldName   string
	data        string
}

func TestReqScannerBodyMultipart1(t *testing.T) {
	// Arrange
	var calls []parsedBodyFieldCbCall
	parsedBodyFieldCb := func(contentType waf.FieldContentType, fieldName string, data string) (err error) {
		calls = append(calls, parsedBodyFieldCbCall{contentType: contentType, fieldName: fieldName, data: data})
		return
	}
	body := bytes.NewBufferString(strings.Replace(strings.Replace(`--------------------------1aa6ce6559102
content-disposition: form-data; name="a"

hello world 1
--------------------------1aa6ce6559102
content-disposition: form-data; name="b"

aaaaaaabccc
--------------------------1aa6ce6559102--
`, "\r", "", -1), "\n", "\r\n", -1))
	boundary := "------------------------1aa6ce6559102"

	// Act
	err := arrangeAndRunBodyParser(t, body, parsedBodyFieldCb, waf.MultipartFormDataBody, boundary)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	contentType := waf.MultipartFormDataContent
	expectedCalls := []parsedBodyFieldCbCall{
		{contentType, "a", "hello world 1"},
		{contentType, "b", "aaaaaaabccc"},
	}

	if len(calls) != len(expectedCalls) {
		t.Fatalf("Got unexpected len(calls): %v. Calls were: %v", len(calls), calls)
	}

	for i, call := range calls {
		if call.contentType != expectedCalls[i].contentType {
			t.Fatalf("Unexpected content type for call %v: %v", i, call.contentType)
		}

		if call.fieldName != expectedCalls[i].fieldName {
			t.Fatalf("Unexpected fieldName for call %v: %v", i, call.fieldName)
		}

		if call.data != expectedCalls[i].data {
			t.Fatalf("Unexpected data for call %v: %v", i, call.data)
		}
	}
}

func TestReqScannerBodyMultipartSkipFile(t *testing.T) {
	// Arrange
	var calls []parsedBodyFieldCbCall
	parsedBodyFieldCb := func(contentType waf.FieldContentType, fieldName string, data string) (err error) {
		calls = append(calls, parsedBodyFieldCbCall{contentType: contentType, fieldName: fieldName, data: data})
		return
	}
	body := bytes.NewBufferString(strings.Replace(strings.Replace(`--------------------------1aa6ce6559102
content-disposition: form-data; name="a"

hello world 1
--------------------------1aa6ce6559102
content-disposition: form-data; name="b"; filename="vcredist_x64.exe"

aaaaaaabccc
--------------------------1aa6ce6559102--
`, "\r", "", -1), "\n", "\r\n", -1))
	boundary := "------------------------1aa6ce6559102"

	// Act
	err := arrangeAndRunBodyParser(t, body, parsedBodyFieldCb, waf.MultipartFormDataBody, boundary)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	expectedCalls := []parsedBodyFieldCbCall{
		{waf.MultipartFormDataContent, "a", "hello world 1"},
		{waf.MultipartFormDataContent, "b", ""},
		{waf.MultipartFormDataFileNames, "b", "vcredist_x64.exe"},
	}

	if len(calls) != len(expectedCalls) {
		t.Fatalf("Got unexpected len(calls): %v. Calls were: %v", len(calls), calls)
	}

	for i, call := range calls {
		if call.contentType != expectedCalls[i].contentType {
			t.Fatalf("Unexpected content type for call %v: %v", i, call.contentType)
		}

		if call.fieldName != expectedCalls[i].fieldName {
			t.Fatalf("Unexpected fieldName for call %v: %v", i, call.fieldName)
		}

		if call.data != expectedCalls[i].data {
			t.Fatalf("Unexpected data for call %v: %v", i, call.data)
		}
	}
}

func TestReqScannerBodyMultipart0Length(t *testing.T) {
	// Arrange
	var calls []parsedBodyFieldCbCall
	parsedBodyFieldCb := func(contentType waf.FieldContentType, fieldName string, data string) (err error) {
		calls = append(calls, parsedBodyFieldCbCall{contentType: contentType, fieldName: fieldName, data: data})
		return
	}
	body := bytes.NewBufferString(``)
	boundary := "------------------------1aa6ce6559102"

	// Act
	err := arrangeAndRunBodyParser(t, body, parsedBodyFieldCb, waf.MultipartFormDataBody, boundary)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	expectedCalls := []parsedBodyFieldCbCall{
		{waf.MultipartFormDataStrictnessWarning, waf.MultipartFormDataStrictnessWarningIncomplete, ""},
	}

	if len(calls) != len(expectedCalls) {
		t.Fatalf("Got unexpected len(calls): %v. Calls were: %v", len(calls), calls)
	}

	for i, call := range calls {
		if call.contentType != expectedCalls[i].contentType {
			t.Fatalf("Unexpected content type for call %v: %v", i, call.contentType)
		}

		if call.fieldName != expectedCalls[i].fieldName {
			t.Fatalf("Unexpected fieldName for call %v: %v", i, call.fieldName)
		}

		if call.data != expectedCalls[i].data {
			t.Fatalf("Unexpected data for call %v: %v", i, call.data)
		}
	}

}

func TestReqScannerBodyJSON1(t *testing.T) {
	// Arrange
	var calls []parsedBodyFieldCbCall
	parsedBodyFieldCb := func(contentType waf.FieldContentType, fieldName string, data string) (err error) {
		calls = append(calls, parsedBodyFieldCbCall{contentType: contentType, fieldName: fieldName, data: data})
		return
	}
	body := bytes.NewBufferString(`
		{
			"a": [1,2,3],
			"b": "aaaaaaabccc"
		}
	`)

	// Act
	err := arrangeAndRunBodyParser(t, body, parsedBodyFieldCb, waf.JSONBody, "")

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	contentType := waf.JSONContent
	expectedCalls := []parsedBodyFieldCbCall{
		{contentType, "", "a"},
		{contentType, "", "b"},
		{contentType, "", "aaaaaaabccc"},
	}

	if len(calls) != len(expectedCalls) {
		t.Fatalf("Got unexpected len(calls): %v. Calls were: %v", len(calls), calls)
	}

	for i, call := range calls {
		if call.contentType != expectedCalls[i].contentType {
			t.Fatalf("Unexpected content type for call %v: %v", i, call.contentType)
		}

		if call.fieldName != expectedCalls[i].fieldName {
			t.Fatalf("Unexpected fieldName for call %v: %v", i, call.fieldName)
		}

		if call.data != expectedCalls[i].data {
			t.Fatalf("Unexpected data for call %v: %v", i, call.data)
		}
	}
}

func TestReqScannerBodyJSONParseErr(t *testing.T) {
	// Arrange
	parsedBodyFieldCb := func(contentType waf.FieldContentType, fieldName string, data string) (err error) {
		return
	}
	body := bytes.NewBufferString(`
		{
			"a": [1,2,3],
			"b": "hello world",
			nonsense
		}
	`)

	// Act
	err := arrangeAndRunBodyParser(t, body, parsedBodyFieldCb, waf.JSONBody, "")

	// Assert
	if err == nil {
		t.Fatalf("Expected error, but got nil")
	}

	if err.Error() != "application/json body scanning error: invalid character 'n'  looking for beginning of object key string" {
		t.Fatalf("Unexpected error message: %v", err.Error())
	}
}

func TestReqScannerBodyJSON0Length(t *testing.T) {
	// Arrange
	var calls []parsedBodyFieldCbCall
	parsedBodyFieldCb := func(contentType waf.FieldContentType, fieldName string, data string) (err error) {
		calls = append(calls, parsedBodyFieldCbCall{contentType: contentType, fieldName: fieldName, data: data})
		return
	}
	body := bytes.NewBufferString(``)

	// Act
	err := arrangeAndRunBodyParser(t, body, parsedBodyFieldCb, waf.JSONBody, "")

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if len(calls) != 0 {
		t.Fatalf("Got unexpected len(calls): %v. Calls were: %v", len(calls), calls)
	}
}

func TestReqScannerBodyXML1(t *testing.T) {
	// Arrange
	var calls []parsedBodyFieldCbCall
	parsedBodyFieldCb := func(contentType waf.FieldContentType, fieldName string, data string) (err error) {
		calls = append(calls, parsedBodyFieldCbCall{contentType: contentType, fieldName: fieldName, data: data})
		return
	}
	body := bytes.NewBufferString(`
		<hello>
			<world abc="def">aaaaaaabccc</world>
		</hello>
	`)

	// Act
	err := arrangeAndRunBodyParser(t, body, parsedBodyFieldCb, waf.XMLBody, "")

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	expectedCalls := []parsedBodyFieldCbCall{
		{waf.XMLCharData, "", "\n\t\t"},
		{waf.XMLCharData, "", "\n\t\t\t"},
		{waf.XMLAttrVal, "", "def"},
		{waf.XMLCharData, "", "aaaaaaabccc"},
		{waf.XMLCharData, "", "\n\t\t"},
		{waf.XMLCharData, "", "\n\t"},
	}

	if len(calls) != len(expectedCalls) {
		t.Fatalf("Got unexpected len(calls): %v. Calls were: %v", len(calls), calls)
	}

	for i, call := range calls {
		if call.contentType != expectedCalls[i].contentType {
			t.Fatalf("Unexpected content type for call %v: %v", i, call.contentType)
		}

		if call.fieldName != expectedCalls[i].fieldName {
			t.Fatalf("Unexpected fieldName for call %v: %v", i, call.fieldName)
		}

		if call.data != expectedCalls[i].data {
			t.Fatalf("Unexpected data for call %v: %v", i, call.data)
		}
	}
}

func TestReqScannerBodyXMLParseError(t *testing.T) {
	// Arrange
	parsedBodyFieldCb := func(contentType waf.FieldContentType, fieldName string, data string) (err error) {
		return
	}
	body := bytes.NewBufferString(`
		<hello>
			<world>hello world</nonsense>
		</hello>
	`)

	// Act
	err := arrangeAndRunBodyParser(t, body, parsedBodyFieldCb, waf.XMLBody, "")

	// Assert
	if err == nil {
		t.Fatalf("Expected error, but got nil")
	}

	if err.Error() != "text/xml body scanning error: XML syntax error on line 3: element <world> closed by </nonsense>" {
		t.Fatalf("Unexpected error message: %v", err.Error())
	}
}

func TestReqScannerBodyXML0Length(t *testing.T) {
	// Arrange
	var calls []parsedBodyFieldCbCall
	parsedBodyFieldCb := func(contentType waf.FieldContentType, fieldName string, data string) (err error) {
		calls = append(calls, parsedBodyFieldCbCall{contentType: contentType, fieldName: fieldName, data: data})
		return
	}
	body := bytes.NewBufferString(``)

	// Act
	err := arrangeAndRunBodyParser(t, body, parsedBodyFieldCb, waf.XMLBody, "")

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if len(calls) != 0 {
		t.Fatalf("Got unexpected len(calls): %v. Calls were: %v", len(calls), calls)
	}
}

func TestReqScannerBodyUrlencode1(t *testing.T) {
	// Arrange
	var calls []parsedBodyFieldCbCall
	parsedBodyFieldCb := func(contentType waf.FieldContentType, fieldName string, data string) (err error) {
		calls = append(calls, parsedBodyFieldCbCall{contentType: contentType, fieldName: fieldName, data: data})
		return
	}
	body := bytes.NewBufferString(`%62=aaa%61aaabcc%xxc&%61=h%65lloworld1`)

	// Act
	err := arrangeAndRunBodyParser(t, body, parsedBodyFieldCb, waf.URLEncodedBody, "")

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Note that the builtin urldecoder returns things in a hasmap, thereby making the order non-deterministic. We therefore sort by keys.
	// If we implement our own io.Reader-based urldecoder in the future, we may no longer be sorting, but rather using the order the values appeared.
	contentType := waf.URLEncodedContent
	expectedCalls := []parsedBodyFieldCbCall{
		{contentType, "b", "aaaaaaabcc%xxc"},
		{contentType, "a", "helloworld1"},
	}

	if len(calls) != len(expectedCalls) {
		t.Fatalf("Got unexpected len(calls): %v. Calls were: %v", len(calls), calls)
	}

	for i, call := range calls {
		if call.contentType != expectedCalls[i].contentType {
			t.Fatalf("Unexpected content type for call %v: %v", i, call.contentType)
		}

		if call.fieldName != expectedCalls[i].fieldName {
			t.Fatalf("Unexpected fieldName for call %v: %v", i, call.fieldName)
		}

		if call.data != expectedCalls[i].data {
			t.Fatalf("Unexpected data for call %v: %v", i, call.data)
		}
	}
}

func TestReqScannerBodyUrlencode0Length(t *testing.T) {
	// Arrange
	var calls []parsedBodyFieldCbCall
	parsedBodyFieldCb := func(contentType waf.FieldContentType, fieldName string, data string) (err error) {
		calls = append(calls, parsedBodyFieldCbCall{contentType: contentType, fieldName: fieldName, data: data})
		return
	}
	body := bytes.NewBufferString(``)

	// Act
	err := arrangeAndRunBodyParser(t, body, parsedBodyFieldCb, waf.URLEncodedBody, "")

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if len(calls) != 0 {
		t.Fatalf("Got unexpected len(calls): %v. Calls were: %v", len(calls), calls)
	}
}

var noOpParsedBodyFieldCb = func(contentType waf.FieldContentType, fieldName string, data string) (err error) {
	return
}

func TestReqScannerBodyMultipartNofileLimit1(t *testing.T) {
	// Arrange
	body1 := &mockReader{Length: 1024 * 256, Content: []byte(`--------------------------1aa6ce6559102
content-disposition: form-data; name="a"

aaaaaaaaaa
`)}
	body2 := bytes.NewBufferString("--------------------------1aa6ce6559102--\r\n")
	body := io.MultiReader(body1, body2)
	boundary := "------------------------1aa6ce6559102"

	// Act
	err := arrangeAndRunBodyParser(t, body, noOpParsedBodyFieldCb, waf.MultipartFormDataBody, boundary)

	// Assert
	if err != waf.ErrPausableBytesLimitExceeded {
		t.Fatalf("Expected a errPausableBytesLimitExceeded but got %T: %v", err, err)
	}
}

func TestReqScannerBodyMultipartFilesDoNotCount(t *testing.T) {
	// Arrange
	body1 := bytes.NewBufferString(`--------------------------1aa6ce6559102
content-disposition: form-data; name="a"

aaaaaaaaaa
--------------------------1aa6ce6559102
content-disposition: form-data; name="b"; filename="vcredist_x64.exe"

`)
	body2 := &mockReader{Length: 1024 * 1024 * 200} // 200 MiB
	body3 := bytes.NewBufferString(`
--------------------------1aa6ce6559102--
`)
	body := io.MultiReader(body1, body2, body3)
	boundary := "------------------------1aa6ce6559102"

	// Act
	err := arrangeAndRunBodyParser(t, body, noOpParsedBodyFieldCb, waf.MultipartFormDataBody, boundary)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}
}

func TestReqScannerBodyMultipartFilesTotalLimit(t *testing.T) {
	// Arrange
	body1 := bytes.NewBufferString(`--------------------------1aa6ce6559102
content-disposition: form-data; name="a"

aaaaaaaaaa
--------------------------1aa6ce6559102
content-disposition: form-data; name="b"; filename="vcredist_x64.exe"

`)
	body2 := &mockReader{Length: 1024 * 1024 * 1024} // 1 GiB
	body3 := bytes.NewBufferString(`
--------------------------1aa6ce6559102--
`)
	body := io.MultiReader(body1, body2, body3)
	boundary := "------------------------1aa6ce6559102"

	// Act
	err := arrangeAndRunBodyParser(t, body, noOpParsedBodyFieldCb, waf.MultipartFormDataBody, boundary)

	// Assert
	if err != waf.ErrTotalBytesLimitExceeded {
		t.Fatalf("Expected a errTotalBytesLimitExceeded but got %T: %v", err, err)
	}
}

func TestReqScannerBodyMultipartSingleFieldLimit(t *testing.T) {
	// Arrange
	body1 := bytes.NewBufferString(`--------------------------1aa6ce6559102
content-disposition: form-data; name="a"

`)
	body2 := &mockReader{Length: 1024 * 30} // 30 KiB
	body3 := bytes.NewBufferString(`
--------------------------1aa6ce6559102--
`)
	body := io.MultiReader(body1, body2, body3)
	boundary := "------------------------1aa6ce6559102"

	// Act
	err := arrangeAndRunBodyParser(t, body, noOpParsedBodyFieldCb, waf.MultipartFormDataBody, boundary)

	// Assert
	if err != waf.ErrFieldBytesLimitExceeded {
		t.Fatalf("Expected a errFieldBytesLimitExceeded but got %T: %v", err, err)
	}
}

func TestReqScannerBodyMultipartHeadersLimit(t *testing.T) {
	// Arrange
	body1 := bytes.NewBufferString(`--------------------------1aa6ce6559102
content-disposition: form-data; name="a"
`)
	body2 := &mockReader{Length: 1024 * 30, Content: []byte("some-header: aaaaaaaaaaaaaa\r\n")} // 30 KiB
	body3 := bytes.NewBufferString(`

some content
--------------------------1aa6ce6559102--
`)
	body := io.MultiReader(body1, body2, body3)
	boundary := "------------------------1aa6ce6559102"

	// Act
	err := arrangeAndRunBodyParser(t, body, noOpParsedBodyFieldCb, waf.MultipartFormDataBody, boundary)

	// Assert
	if err != waf.ErrFieldBytesLimitExceeded {
		t.Fatalf("Expected a errTotalBytesLimitExceeded but got %T: %v", err, err)
	}
}

func TestReqScannerBodyJSONLimit(t *testing.T) {
	// Arrange
	body1 := bytes.NewBufferString(`{"myarray": [`)
	body2 := &mockReader{Length: 1024 * 1024, Content: []byte(`"hello world", `)} // 1 MiB
	body3 := bytes.NewBufferString(`"hello world"]}`)
	body := io.MultiReader(body1, body2, body3)

	// Act
	err := arrangeAndRunBodyParser(t, body, noOpParsedBodyFieldCb, waf.JSONBody, "")

	// Assert
	if err != waf.ErrPausableBytesLimitExceeded {
		t.Fatalf("Expected a errPausableBytesLimitExceeded but got %T: %v", err, err)
	}
}

func TestReqScannerBodyJSONSingleFieldLimit(t *testing.T) {
	// Arrange
	body1 := bytes.NewBufferString(`{"myarray": "`)
	body2 := &mockReader{Length: 1024 * 30} // 30 KiB
	body3 := bytes.NewBufferString(`"}`)
	body := io.MultiReader(body1, body2, body3)

	// Act
	err := arrangeAndRunBodyParser(t, body, noOpParsedBodyFieldCb, waf.JSONBody, "")

	// Assert
	if err != waf.ErrFieldBytesLimitExceeded {
		t.Fatalf("Expected a errPausableBytesLimitExceeded but got %T: %v", err, err)
	}
}

func TestReqScannerBodyXMLLimit(t *testing.T) {
	// Arrange
	body1 := bytes.NewBufferString(`<hello>`)
	body2 := &mockReader{Length: 1024 * 1024, Content: []byte(`<world>something</world>`)} // 1 MiB
	body3 := bytes.NewBufferString(`</hello>`)
	body := io.MultiReader(body1, body2, body3)

	// Act
	err := arrangeAndRunBodyParser(t, body, noOpParsedBodyFieldCb, waf.XMLBody, "")

	// Assert
	if err != waf.ErrPausableBytesLimitExceeded {
		t.Fatalf("Expected a errPausableBytesLimitExceeded but got %T: %v", err, err)
	}
}

func TestReqScannerBodyXMLSingleFieldLimit(t *testing.T) {
	// Arrange
	body1 := bytes.NewBufferString(`<hello>`)
	body2 := &mockReader{Length: 1024 * 30} // 30 KiB
	body3 := bytes.NewBufferString(`</hello>`)
	body := io.MultiReader(body1, body2, body3)

	// Act
	err := arrangeAndRunBodyParser(t, body, noOpParsedBodyFieldCb, waf.XMLBody, "")

	// Assert
	if err != waf.ErrFieldBytesLimitExceeded {
		t.Fatalf("Expected a errPausableBytesLimitExceeded but got %T: %v", err, err)
	}
}

func TestReqScannerBodyUrlEncodeLimit(t *testing.T) {
	// Arrange
	body2 := &mockReader{Length: 1024 * 1024, Content: []byte(`a=helloworld1&`)} // 1 MiB
	body3 := bytes.NewBufferString(`a=helloworld1`)
	body := io.MultiReader(body2, body3)

	// Act
	err := arrangeAndRunBodyParser(t, body, noOpParsedBodyFieldCb, waf.URLEncodedBody, "")

	// Assert
	if err != waf.ErrPausableBytesLimitExceeded {
		t.Fatalf("Expected a errPausableBytesLimitExceeded but got %T: %v", err, err)
	}
}

func TestReqScannerContentLengthHeaderSaysTooLong(t *testing.T) {
	// Arrange
	contentLength := 1024 * 1024 * 1024            // 1 GiB
	body := bytes.NewBufferString(`a=helloworld1`) // Note that the body in reality is not actually 1 GiB
	rbp := NewRequestBodyParser(waf.DefaultLengthLimits)
	logger := testutils.NewTestLogger(t)

	// Act
	err := rbp.Parse(logger, body, noOpParsedBodyFieldCb, waf.URLEncodedBody, contentLength, "", true)

	// Assert
	if err != waf.ErrTotalBytesLimitExceeded {
		t.Fatalf("Expected a errTotalBytesLimitExceeded but got %T: %v", err, err)
	}
}

func TestReqScannerBodyRaw(t *testing.T) {
	// Arrange
	var calls []parsedBodyFieldCbCall
	parsedBodyFieldCb := func(contentType waf.FieldContentType, fieldName string, data string) (err error) {
		calls = append(calls, parsedBodyFieldCbCall{contentType: contentType, fieldName: fieldName, data: data})
		return
	}
	body := bytes.NewBufferString(`b=aaaaaaabccc&a=helloworld1`)
	rbp := NewRequestBodyParser(waf.DefaultLengthLimits)
	logger := testutils.NewTestLogger(t)

	// Act
	err := rbp.Parse(logger, body, parsedBodyFieldCb, waf.URLEncodedBody, 0, "", true)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	// Note that the builtin urldecoder returns things in a hasmap, thereby making the order non-deterministic. We therefore sort by keys.
	// If we implement our own io.Reader-based urldecoder in the future, we may no longer be sorting, but rather using the order the values appeared.
	expectedCalls := []parsedBodyFieldCbCall{
		{waf.URLEncodedContent, "b", "aaaaaaabccc"},
		{waf.URLEncodedContent, "a", "helloworld1"},
		{waf.FullRawRequestBody, "", "b=aaaaaaabccc&a=helloworld1"},
	}

	if len(calls) != len(expectedCalls) {
		t.Fatalf("Got unexpected len(calls): %v. Calls were: %v", len(calls), calls)
	}

	for i, call := range calls {
		if call.contentType != expectedCalls[i].contentType {
			t.Fatalf("Unexpected content type for call %v: %v", i, call.contentType)
		}

		if call.fieldName != expectedCalls[i].fieldName {
			t.Fatalf("Unexpected fieldName for call %v: %v", i, call.fieldName)
		}

		if call.data != expectedCalls[i].data {
			t.Fatalf("Unexpected data for call %v: %v", i, call.data)
		}
	}
}

type mockWafHTTPRequest struct {
	uri        string
	bodyReader io.Reader
	remoteAddr string
	headers    []waf.HeaderPair
}

func (r *mockWafHTTPRequest) Headers() []waf.HeaderPair { return r.headers }
func (r *mockWafHTTPRequest) BodyReader() io.Reader     { return r.bodyReader }

type mockHeaderPair struct {
	k string
	v string
}

func (h *mockHeaderPair) Key() string   { return h.k }
func (h *mockHeaderPair) Value() string { return h.v }

type mockLogMetaData struct {
}

func (h *mockLogMetaData) Scope() string     { return "Global" }
func (h *mockLogMetaData) ScopeName() string { return "Default Policy" }

// A io.Reader implementation that that just fills up the given buffer with copies of the Content byte slice until Length is reached.
type mockReader struct {
	Pos     int
	Length  int
	Content []byte
	next    []byte
}

// Fills up the given buffer with 'a'-chars on each call until Length is reached.
func (m *mockReader) Read(p []byte) (n int, err error) {
	if m.Content == nil {
		m.Content = []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	}

	if m.Pos >= m.Length {
		err = io.EOF
		return
	}

	for {
		if m.Pos+len(m.Content) > m.Length {
			err = io.EOF
			return
		}

		if len(m.next) == 0 {
			m.next = m.Content
		}

		c := copy(p[n:], m.next)
		n += c
		m.Pos += c
		m.next = m.next[c:]

		if n == len(p) {
			break
		}
	}

	return
}

// Tests that the mockReader works, which itself is just used for other tests.
func TestMockReader(t *testing.T) {
	// Arrange
	content := []byte("hello,")
	targetLen := 1024 * 1024 * 2
	m := &mockReader{Length: targetLen, Content: content}
	b := &bytes.Buffer{}

	// Act
	_, err := b.ReadFrom(m)

	// Assert
	if err != nil {
		t.Fatalf("Unexpected err %T: %v", err, err)
	}

	if b.Len() != targetLen-targetLen%len(content) {
		t.Fatalf("Unexpected length: %v", b.Len())

	}
}
