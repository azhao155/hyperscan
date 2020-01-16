package bodyparsing

import (
	"bytes"
	"io/ioutil"
	"strings"
	"testing"
)

func TestReqScannerBodyMultipartStrict(t *testing.T) {
	// Arrange
	body := bytes.NewBufferString(strings.Replace(strings.Replace(`--------------------------1aa6ce6559102
content-disposition: form-data; name="a"

helloworld
--------------------------1aa6ce6559102
content-disposition: form-data; name="b"

aaaaaaabccc
--------------------------1aa6ce6559102--
`, "\r", "", -1), "\n", "\r\n", -1))
	m := &multipartStrictReaderDecorator{
		reader:   body,
		boundary: "------------------------1aa6ce6559102",
	}

	// Act
	_, err := ioutil.ReadAll(m)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if m.completed() != true {
		t.Fatalf("Got unexpected completed()")
	}

	if m.multipartDataBefore != false {
		t.Fatalf("Got unexpected multipartDataBefore")
	}

	if m.multipartDataAfter != false {
		t.Fatalf("Got unexpected multipartDataAfter")
	}

	if m.multipartHeaderFolding != false {
		t.Fatalf("Got unexpected multipartHeaderFolding")
	}

	if m.multipartLfLine != false {
		t.Fatalf("Got unexpected multipartLfLine")
	}

	if m.multipartInvalidHeaderFolding != false {
		t.Fatalf("Got unexpected multipartInvalidHeaderFolding")
	}

	if m.multipartUnmatchedBoundary != false {
		t.Fatalf("Got unexpected multipartUnmatchedBoundary")
	}
}

func TestReqScannerBodyMultipartStrictDataBefore1(t *testing.T) {
	// Arrange
	body := bytes.NewBufferString(strings.Replace(strings.Replace(`aaaaaaaaaaaaaaaaaaaaaa
--------------------------1aa6ce6559102
content-disposition: form-data; name="a"

helloworld
--------------------------1aa6ce6559102
content-disposition: form-data; name="b"

aaaaaaabccc
--------------------------1aa6ce6559102--
`, "\r", "", -1), "\n", "\r\n", -1))
	m := &multipartStrictReaderDecorator{
		reader:   body,
		boundary: "------------------------1aa6ce6559102",
	}

	// Act
	_, err := ioutil.ReadAll(m)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if m.completed() != true {
		t.Fatalf("Got unexpected completed()")
	}

	if m.multipartDataBefore != true {
		t.Fatalf("Got unexpected multipartDataBefore")
	}

	if m.multipartDataAfter != false {
		t.Fatalf("Got unexpected multipartDataAfter")
	}

	if m.multipartHeaderFolding != false {
		t.Fatalf("Got unexpected multipartHeaderFolding")
	}

	if m.multipartLfLine != false {
		t.Fatalf("Got unexpected multipartLfLine")
	}

	if m.multipartInvalidHeaderFolding != false {
		t.Fatalf("Got unexpected multipartInvalidHeaderFolding")
	}

	if m.multipartUnmatchedBoundary != false {
		t.Fatalf("Got unexpected multipartUnmatchedBoundary")
	}
}

func TestReqScannerBodyMultipartStrictDataBefore2(t *testing.T) {
	// Arrange
	body := bytes.NewBufferString(strings.Replace(strings.Replace(`
--------------------------1aa6ce6559102
content-disposition: form-data; name="a"

helloworld
--------------------------1aa6ce6559102
content-disposition: form-data; name="b"

aaaaaaabccc
--------------------------1aa6ce6559102--
`, "\r", "", -1), "\n", "\r\n", -1))
	m := &multipartStrictReaderDecorator{
		reader:   body,
		boundary: "------------------------1aa6ce6559102",
	}

	// Act
	_, err := ioutil.ReadAll(m)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if m.completed() != true {
		t.Fatalf("Got unexpected completed()")
	}

	if m.multipartDataBefore != true {
		t.Fatalf("Got unexpected multipartDataBefore")
	}

	if m.multipartDataAfter != false {
		t.Fatalf("Got unexpected multipartDataAfter")
	}

	if m.multipartHeaderFolding != false {
		t.Fatalf("Got unexpected multipartHeaderFolding")
	}

	if m.multipartLfLine != false {
		t.Fatalf("Got unexpected multipartLfLine")
	}

	if m.multipartInvalidHeaderFolding != false {
		t.Fatalf("Got unexpected multipartInvalidHeaderFolding")
	}

	if m.multipartUnmatchedBoundary != false {
		t.Fatalf("Got unexpected multipartUnmatchedBoundary")
	}
}

func TestReqScannerBodyMultipartStrictLfLineBoundary(t *testing.T) {
	// Arrange
	// Note there is only "\n" (as opposed to "\r\n") after the boundary line.
	body := bytes.NewBufferString("--------------------------1aa6ce6559102\ncontent-disposition: form-data; name=\"a\"\r\n\r\nhelloworld\r\n--------------------------1aa6ce6559102--\r\n")
	m := &multipartStrictReaderDecorator{
		reader:   body,
		boundary: "------------------------1aa6ce6559102",
	}

	// Act
	_, err := ioutil.ReadAll(m)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if m.completed() != true {
		t.Fatalf("Got unexpected completed()")
	}

	if m.multipartDataBefore != false {
		t.Fatalf("Got unexpected multipartDataBefore")
	}

	if m.multipartDataAfter != false {
		t.Fatalf("Got unexpected multipartDataAfter")
	}

	if m.multipartHeaderFolding != false {
		t.Fatalf("Got unexpected multipartHeaderFolding")
	}

	if m.multipartLfLine != true {
		t.Fatalf("Got unexpected multipartLfLine")
	}

	if m.multipartInvalidHeaderFolding != false {
		t.Fatalf("Got unexpected multipartInvalidHeaderFolding")
	}

	if m.multipartUnmatchedBoundary != false {
		t.Fatalf("Got unexpected multipartUnmatchedBoundary")
	}
}

func TestReqScannerBodyMultipartStrictLfLineHeader(t *testing.T) {
	// Arrange
	// Note there is only "\n" (as opposed to "\r\n") after the part header line.
	body := bytes.NewBufferString("--------------------------1aa6ce6559102\r\ncontent-disposition: form-data; name=\"a\"\n\r\nhelloworld\r\n--------------------------1aa6ce6559102--\r\n")
	m := &multipartStrictReaderDecorator{
		reader:   body,
		boundary: "------------------------1aa6ce6559102",
	}

	// Act
	_, err := ioutil.ReadAll(m)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if m.completed() != true {
		t.Fatalf("Got unexpected completed()")
	}

	if m.multipartDataBefore != false {
		t.Fatalf("Got unexpected multipartDataBefore")
	}

	if m.multipartDataAfter != false {
		t.Fatalf("Got unexpected multipartDataAfter")
	}

	if m.multipartHeaderFolding != false {
		t.Fatalf("Got unexpected multipartHeaderFolding")
	}

	if m.multipartLfLine != true {
		t.Fatalf("Got unexpected multipartLfLine")
	}

	if m.multipartInvalidHeaderFolding != false {
		t.Fatalf("Got unexpected multipartInvalidHeaderFolding")
	}

	if m.multipartUnmatchedBoundary != false {
		t.Fatalf("Got unexpected multipartUnmatchedBoundary")
	}
}

func TestReqScannerBodyMultipartStrictLfLineLastBoundary(t *testing.T) {
	// Arrange
	// Note there is only "\n" (as opposed to "\r\n") after the final boundary line.
	body := bytes.NewBufferString("--------------------------1aa6ce6559102\r\ncontent-disposition: form-data; name=\"a\"\r\n\r\nhelloworld\r\n--------------------------1aa6ce6559102--\n")
	m := &multipartStrictReaderDecorator{
		reader:   body,
		boundary: "------------------------1aa6ce6559102",
	}

	// Act
	_, err := ioutil.ReadAll(m)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if m.completed() != true {
		t.Fatalf("Got unexpected completed()")
	}

	if m.multipartDataBefore != false {
		t.Fatalf("Got unexpected multipartDataBefore")
	}

	if m.multipartDataAfter != false {
		t.Fatalf("Got unexpected multipartDataAfter")
	}

	if m.multipartHeaderFolding != false {
		t.Fatalf("Got unexpected multipartHeaderFolding")
	}

	if m.multipartLfLine != true {
		t.Fatalf("Got unexpected multipartLfLine")
	}

	if m.multipartInvalidHeaderFolding != false {
		t.Fatalf("Got unexpected multipartInvalidHeaderFolding")
	}

	if m.multipartUnmatchedBoundary != false {
		t.Fatalf("Got unexpected multipartUnmatchedBoundary")
	}
}

func TestReqScannerBodyMultipartStrictLfLineMissingCrAfterEmptyHeader(t *testing.T) {
	// Arrange
	// Note there is only "\n" (as opposed to "\r\n") after the empty part header line.
	body := bytes.NewBufferString("--------------------------1aa6ce6559102\r\ncontent-disposition: form-data; name=\"a\"\r\n\nhelloworld\r\n--------------------------1aa6ce6559102--\r\n")
	m := &multipartStrictReaderDecorator{
		reader:   body,
		boundary: "------------------------1aa6ce6559102",
	}

	// Act
	_, err := ioutil.ReadAll(m)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if m.completed() != true {
		t.Fatalf("Got unexpected completed()")
	}

	if m.multipartDataBefore != false {
		t.Fatalf("Got unexpected multipartDataBefore")
	}

	if m.multipartDataAfter != false {
		t.Fatalf("Got unexpected multipartDataAfter")
	}

	if m.multipartHeaderFolding != false {
		t.Fatalf("Got unexpected multipartHeaderFolding")
	}

	if m.multipartLfLine != true {
		t.Fatalf("Got unexpected multipartLfLine")
	}

	if m.multipartInvalidHeaderFolding != false {
		t.Fatalf("Got unexpected multipartInvalidHeaderFolding")
	}

	if m.multipartUnmatchedBoundary != false {
		t.Fatalf("Got unexpected multipartUnmatchedBoundary")
	}
}

func TestReqScannerBodyMultipartStrictLfLineHeaderMissingLfAfterCr1(t *testing.T) {
	// Arrange
	// Note there is only a "\r" (as opposed to "\r\n") after the part header line.
	body := bytes.NewBufferString("--------------------------1aa6ce6559102\r\ncontent-disposition: form-data; name=\"a\"\r\r\nhelloworld\r\n--------------------------1aa6ce6559102--\r\n")
	m := &multipartStrictReaderDecorator{
		reader:   body,
		boundary: "------------------------1aa6ce6559102",
	}

	// Act
	_, err := ioutil.ReadAll(m)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if m.completed() != false {
		t.Fatalf("Got unexpected completed()")
	}

	if m.multipartDataBefore != false {
		t.Fatalf("Got unexpected multipartDataBefore")
	}

	if m.multipartDataAfter != false {
		t.Fatalf("Got unexpected multipartDataAfter")
	}

	if m.multipartHeaderFolding != false {
		t.Fatalf("Got unexpected multipartHeaderFolding")
	}

	if m.multipartLfLine != true {
		t.Fatalf("Got unexpected multipartLfLine")
	}

	if m.multipartInvalidHeaderFolding != false {
		t.Fatalf("Got unexpected multipartInvalidHeaderFolding")
	}

	if m.multipartUnmatchedBoundary != false {
		t.Fatalf("Got unexpected multipartUnmatchedBoundary")
	}
}

func TestReqScannerBodyMultipartStrictLfLineHeaderMissingLfAfterCr2(t *testing.T) {
	// Arrange
	// Note there is only "\r" (as opposed to "\r\n") after the empty part header line.
	body := bytes.NewBufferString("--------------------------1aa6ce6559102\r\ncontent-disposition: form-data; name=\"a\"\r\n\rhelloworld\r\n--------------------------1aa6ce6559102--\r\n")
	m := &multipartStrictReaderDecorator{
		reader:   body,
		boundary: "------------------------1aa6ce6559102",
	}

	// Act
	_, err := ioutil.ReadAll(m)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if m.completed() != false {
		t.Fatalf("Got unexpected completed()")
	}

	if m.multipartDataBefore != false {
		t.Fatalf("Got unexpected multipartDataBefore")
	}

	if m.multipartDataAfter != false {
		t.Fatalf("Got unexpected multipartDataAfter")
	}

	if m.multipartHeaderFolding != false {
		t.Fatalf("Got unexpected multipartHeaderFolding")
	}

	if m.multipartLfLine != true {
		t.Fatalf("Got unexpected multipartLfLine")
	}

	if m.multipartInvalidHeaderFolding != false {
		t.Fatalf("Got unexpected multipartInvalidHeaderFolding")
	}

	if m.multipartUnmatchedBoundary != false {
		t.Fatalf("Got unexpected multipartUnmatchedBoundary")
	}
}

func TestReqScannerBodyMultipartStrictUnmatchedBoundary1(t *testing.T) {
	// Arrange
	// Note that first boundary has too few dashes.
	body := bytes.NewBufferString(strings.Replace(strings.Replace(`-------------------------1aa6ce6559102
content-disposition: form-data; name="a"

helloworld
--------------------------1aa6ce6559102
content-disposition: form-data; name="b"

aaaaaaabccc
--------------------------1aa6ce6559102--
`, "\r", "", -1), "\n", "\r\n", -1))
	m := &multipartStrictReaderDecorator{
		reader:   body,
		boundary: "------------------------1aa6ce6559102",
	}

	// Act
	_, err := ioutil.ReadAll(m)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if m.completed() != true {
		t.Fatalf("Got unexpected completed()")
	}

	if m.multipartDataBefore != true {
		t.Fatalf("Got unexpected multipartDataBefore")
	}

	if m.multipartDataAfter != false {
		t.Fatalf("Got unexpected multipartDataAfter")
	}

	if m.multipartHeaderFolding != false {
		t.Fatalf("Got unexpected multipartHeaderFolding")
	}

	if m.multipartLfLine != false {
		t.Fatalf("Got unexpected multipartLfLine")
	}

	if m.multipartInvalidHeaderFolding != false {
		t.Fatalf("Got unexpected multipartInvalidHeaderFolding")
	}

	if m.multipartUnmatchedBoundary != true {
		t.Fatalf("Got unexpected multipartUnmatchedBoundary")
	}
}

func TestReqScannerBodyMultipartStrictUnmatchedBoundary2(t *testing.T) {
	// Arrange
	body := bytes.NewBufferString(strings.Replace(strings.Replace(`--------------------------1aa6ce6559102
content-disposition: form-data; name="a"

helloworld
--notRealBoundary
content-disposition: form-data; name="b"

aaaaaaabccc
--------------------------1aa6ce6559102--
`, "\r", "", -1), "\n", "\r\n", -1))
	m := &multipartStrictReaderDecorator{
		reader:   body,
		boundary: "------------------------1aa6ce6559102",
	}

	// Act
	_, err := ioutil.ReadAll(m)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if m.completed() != true {
		t.Fatalf("Got unexpected completed()")
	}

	if m.multipartDataBefore != false {
		t.Fatalf("Got unexpected multipartDataBefore")
	}

	if m.multipartDataAfter != false {
		t.Fatalf("Got unexpected multipartDataAfter")
	}

	if m.multipartHeaderFolding != false {
		t.Fatalf("Got unexpected multipartHeaderFolding")
	}

	if m.multipartLfLine != false {
		t.Fatalf("Got unexpected multipartLfLine")
	}

	if m.multipartInvalidHeaderFolding != false {
		t.Fatalf("Got unexpected multipartInvalidHeaderFolding")
	}

	if m.multipartUnmatchedBoundary != true {
		t.Fatalf("Got unexpected multipartUnmatchedBoundary")
	}
}

func TestReqScannerBodyMultipartStrictUnmatchedBoundary3(t *testing.T) {
	// Arrange
	body := bytes.NewBufferString(strings.Replace(strings.Replace(`--------------------------1aa6ce6559102
content-disposition: form-data; name="a"

helloworld
--------------------------1aa6ce6559102aaaaaaaaaaaa
content-disposition: form-data; name="b"

aaaaaaabccc
--------------------------1aa6ce6559102--
`, "\r", "", -1), "\n", "\r\n", -1))
	m := &multipartStrictReaderDecorator{
		reader:   body,
		boundary: "------------------------1aa6ce6559102",
	}

	// Act
	_, err := ioutil.ReadAll(m)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if m.completed() != true {
		t.Fatalf("Got unexpected completed()")
	}

	if m.multipartDataBefore != false {
		t.Fatalf("Got unexpected multipartDataBefore")
	}

	if m.multipartDataAfter != false {
		t.Fatalf("Got unexpected multipartDataAfter")
	}

	if m.multipartHeaderFolding != false {
		t.Fatalf("Got unexpected multipartHeaderFolding")
	}

	if m.multipartLfLine != false {
		t.Fatalf("Got unexpected multipartLfLine")
	}

	if m.multipartInvalidHeaderFolding != false {
		t.Fatalf("Got unexpected multipartInvalidHeaderFolding")
	}

	if m.multipartUnmatchedBoundary != true {
		t.Fatalf("Got unexpected multipartUnmatchedBoundary")
	}
}

func TestReqScannerBodyMultipartStrictUnmatchedBoundary4(t *testing.T) {
	// Arrange
	body := bytes.NewBufferString(strings.Replace(strings.Replace(`--------------------------1aa6ce6559102aaaaaaaaaaaa
content-disposition: form-data; name="a"

helloworld
--------------------------1aa6ce6559102
content-disposition: form-data; name="b"

aaaaaaabccc
--------------------------1aa6ce6559102--
`, "\r", "", -1), "\n", "\r\n", -1))
	m := &multipartStrictReaderDecorator{
		reader:   body,
		boundary: "------------------------1aa6ce6559102",
	}

	// Act
	_, err := ioutil.ReadAll(m)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if m.completed() != true {
		t.Fatalf("Got unexpected completed()")
	}

	if m.multipartDataBefore != true {
		t.Fatalf("Got unexpected multipartDataBefore")
	}

	if m.multipartDataAfter != false {
		t.Fatalf("Got unexpected multipartDataAfter")
	}

	if m.multipartHeaderFolding != false {
		t.Fatalf("Got unexpected multipartHeaderFolding")
	}

	if m.multipartLfLine != false {
		t.Fatalf("Got unexpected multipartLfLine")
	}

	if m.multipartInvalidHeaderFolding != false {
		t.Fatalf("Got unexpected multipartInvalidHeaderFolding")
	}

	if m.multipartUnmatchedBoundary != true {
		t.Fatalf("Got unexpected multipartUnmatchedBoundary")
	}
}

func TestReqScannerBodyMultipartStrictUnmatchedBoundary5(t *testing.T) {
	// Arrange
	// The boundary is followed by just a "\r", without a "\n".
	body := bytes.NewBufferString("--------------------------1aa6ce6559102\rcontent-disposition: form-data; name=\"a\"\r\n\r\nhelloworld\r\n--------------------------1aa6ce6559102--\r\n")
	m := &multipartStrictReaderDecorator{
		reader:   body,
		boundary: "------------------------1aa6ce6559102",
	}

	// Act
	_, err := ioutil.ReadAll(m)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if m.completed() != true {
		t.Fatalf("Got unexpected completed()")
	}

	if m.multipartDataBefore != true {
		t.Fatalf("Got unexpected multipartDataBefore")
	}

	if m.multipartDataAfter != false {
		t.Fatalf("Got unexpected multipartDataAfter")
	}

	if m.multipartHeaderFolding != false {
		t.Fatalf("Got unexpected multipartHeaderFolding")
	}

	if m.multipartLfLine != false {
		t.Fatalf("Got unexpected multipartLfLine")
	}

	if m.multipartInvalidHeaderFolding != false {
		t.Fatalf("Got unexpected multipartInvalidHeaderFolding")
	}

	if m.multipartUnmatchedBoundary != true {
		t.Fatalf("Got unexpected multipartUnmatchedBoundary")
	}
}

func TestReqScannerBodyMultipartStrictUnmatchedBoundary6(t *testing.T) {
	// Arrange
	body := bytes.NewBufferString(strings.Replace(strings.Replace(`--------------------------1aa6ce6559102-
content-disposition: form-data; name="a"

helloworld
--------------------------1aa6ce6559102
content-disposition: form-data; name="b"

aaaaaaabccc
--------------------------1aa6ce6559102--
`, "\r", "", -1), "\n", "\r\n", -1))
	m := &multipartStrictReaderDecorator{
		reader:   body,
		boundary: "------------------------1aa6ce6559102",
	}

	// Act
	_, err := ioutil.ReadAll(m)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if m.completed() != true {
		t.Fatalf("Got unexpected completed()")
	}

	if m.multipartDataBefore != true {
		t.Fatalf("Got unexpected multipartDataBefore")
	}

	if m.multipartDataAfter != false {
		t.Fatalf("Got unexpected multipartDataAfter")
	}

	if m.multipartHeaderFolding != false {
		t.Fatalf("Got unexpected multipartHeaderFolding")
	}

	if m.multipartLfLine != false {
		t.Fatalf("Got unexpected multipartLfLine")
	}

	if m.multipartInvalidHeaderFolding != false {
		t.Fatalf("Got unexpected multipartInvalidHeaderFolding")
	}

	if m.multipartUnmatchedBoundary != true {
		t.Fatalf("Got unexpected multipartUnmatchedBoundary")
	}
}

func TestReqScannerBodyMultipartStrictUnmatchedBoundary7(t *testing.T) {
	// Arrange
	// The first boundary looks almost like a final boundary, but with only an "\r" rather than "\r\n".
	body := bytes.NewBufferString("--------------------------1aa6ce6559102--\rcontent-disposition: form-data; name=\"a\"\r\n\r\nhelloworld\r\n--------------------------1aa6ce6559102--\r\n")
	m := &multipartStrictReaderDecorator{
		reader:   body,
		boundary: "------------------------1aa6ce6559102",
	}

	// Act
	_, err := ioutil.ReadAll(m)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if m.completed() != true {
		t.Fatalf("Got unexpected completed()")
	}

	if m.multipartDataBefore != true {
		t.Fatalf("Got unexpected multipartDataBefore")
	}

	if m.multipartDataAfter != false {
		t.Fatalf("Got unexpected multipartDataAfter")
	}

	if m.multipartHeaderFolding != false {
		t.Fatalf("Got unexpected multipartHeaderFolding")
	}

	if m.multipartLfLine != false {
		t.Fatalf("Got unexpected multipartLfLine")
	}

	if m.multipartInvalidHeaderFolding != false {
		t.Fatalf("Got unexpected multipartInvalidHeaderFolding")
	}

	if m.multipartUnmatchedBoundary != true {
		t.Fatalf("Got unexpected multipartUnmatchedBoundary")
	}
}

func TestReqScannerBodyMultipartStrictUnmatchedBoundary8(t *testing.T) {
	// Arrange
	// The first boundary looks almost like a final boundary, but with nonsense afterwards.
	body := bytes.NewBufferString("--------------------------1aa6ce6559102--nonsense\r\n--------------------------1aa6ce6559102content-disposition: form-data; name=\"a\"\r\n\r\nhelloworld\r\n--------------------------1aa6ce6559102--\r\n")
	m := &multipartStrictReaderDecorator{
		reader:   body,
		boundary: "------------------------1aa6ce6559102",
	}

	// Act
	_, err := ioutil.ReadAll(m)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if m.completed() != true {
		t.Fatalf("Got unexpected completed()")
	}

	if m.multipartDataBefore != true {
		t.Fatalf("Got unexpected multipartDataBefore")
	}

	if m.multipartDataAfter != false {
		t.Fatalf("Got unexpected multipartDataAfter")
	}

	if m.multipartHeaderFolding != false {
		t.Fatalf("Got unexpected multipartHeaderFolding")
	}

	if m.multipartLfLine != false {
		t.Fatalf("Got unexpected multipartLfLine")
	}

	if m.multipartInvalidHeaderFolding != false {
		t.Fatalf("Got unexpected multipartInvalidHeaderFolding")
	}

	if m.multipartUnmatchedBoundary != true {
		t.Fatalf("Got unexpected multipartUnmatchedBoundary")
	}
}

func TestReqScannerBodyMultipartStrictDataAfter1(t *testing.T) {
	// Arrange
	body := bytes.NewBufferString(strings.Replace(strings.Replace(`--------------------------1aa6ce6559102
content-disposition: form-data; name="a"

helloworld
--------------------------1aa6ce6559102
content-disposition: form-data; name="b"

aaaaaaabccc
--------------------------1aa6ce6559102--
aaaaaaaaaaaaaaaaaaaaaa
`, "\r", "", -1), "\n", "\r\n", -1))
	m := &multipartStrictReaderDecorator{
		reader:   body,
		boundary: "------------------------1aa6ce6559102",
	}

	// Act
	_, err := ioutil.ReadAll(m)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if m.completed() != true {
		t.Fatalf("Got unexpected completed()")
	}

	if m.multipartDataBefore != false {
		t.Fatalf("Got unexpected multipartDataBefore")
	}

	if m.multipartDataAfter != true {
		t.Fatalf("Got unexpected multipartDataAfter")
	}

	if m.multipartHeaderFolding != false {
		t.Fatalf("Got unexpected multipartHeaderFolding")
	}

	if m.multipartLfLine != false {
		t.Fatalf("Got unexpected multipartLfLine")
	}

	if m.multipartInvalidHeaderFolding != false {
		t.Fatalf("Got unexpected multipartInvalidHeaderFolding")
	}

	if m.multipartUnmatchedBoundary != false {
		t.Fatalf("Got unexpected multipartUnmatchedBoundary")
	}
}

func TestReqScannerBodyMultipartStrictDataAfter2(t *testing.T) {
	// Arrange
	body := bytes.NewBufferString(strings.Replace(strings.Replace(`--------------------------1aa6ce6559102
content-disposition: form-data; name="a"

helloworld
--------------------------1aa6ce6559102
content-disposition: form-data; name="b"

aaaaaaabccc
--------------------------1aa6ce6559102--


`, "\r", "", -1), "\n", "\r\n", -1))
	m := &multipartStrictReaderDecorator{
		reader:   body,
		boundary: "------------------------1aa6ce6559102",
	}

	// Act
	_, err := ioutil.ReadAll(m)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if m.completed() != true {
		t.Fatalf("Got unexpected completed()")
	}

	if m.multipartDataBefore != false {
		t.Fatalf("Got unexpected multipartDataBefore")
	}

	if m.multipartDataAfter != true {
		t.Fatalf("Got unexpected multipartDataAfter")
	}

	if m.multipartHeaderFolding != false {
		t.Fatalf("Got unexpected multipartHeaderFolding")
	}

	if m.multipartLfLine != false {
		t.Fatalf("Got unexpected multipartLfLine")
	}

	if m.multipartInvalidHeaderFolding != false {
		t.Fatalf("Got unexpected multipartInvalidHeaderFolding")
	}

	if m.multipartUnmatchedBoundary != false {
		t.Fatalf("Got unexpected multipartUnmatchedBoundary")
	}
}

func TestReqScannerBodyMultipartStrictHeaderFolding1(t *testing.T) {
	// Arrange
	body := bytes.NewBufferString(strings.Replace(strings.Replace(`--------------------------1aa6ce6559102
content-disposition: form-data; name="a"
someheader: hello
  world

helloworld
--------------------------1aa6ce6559102
content-disposition: form-data; name="b"

aaaaaaabccc
--------------------------1aa6ce6559102--
`, "\r", "", -1), "\n", "\r\n", -1))
	m := &multipartStrictReaderDecorator{
		reader:   body,
		boundary: "------------------------1aa6ce6559102",
	}

	// Act
	_, err := ioutil.ReadAll(m)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if m.completed() != true {
		t.Fatalf("Got unexpected completed()")
	}

	if m.multipartDataBefore != false {
		t.Fatalf("Got unexpected multipartDataBefore")
	}

	if m.multipartDataAfter != false {
		t.Fatalf("Got unexpected multipartDataAfter")
	}

	if m.multipartHeaderFolding != true {
		t.Fatalf("Got unexpected multipartHeaderFolding")
	}

	if m.multipartLfLine != false {
		t.Fatalf("Got unexpected multipartLfLine")
	}

	if m.multipartInvalidHeaderFolding != false {
		t.Fatalf("Got unexpected multipartInvalidHeaderFolding")
	}

	if m.multipartUnmatchedBoundary != false {
		t.Fatalf("Got unexpected multipartUnmatchedBoundary")
	}
}

func TestReqScannerBodyMultipartStrictHeaderFolding2(t *testing.T) {
	// Arrange
	// The "someheader" is continued on the next line prepended by a tab.
	body := bytes.NewBufferString("--------------------------1aa6ce6559102\r\ncontent-disposition: form-data; name=\"a\"\r\nsomeheader: hello\r\n\tworld\r\n\r\nhelloworld\r\n--------------------------1aa6ce6559102--\r\n")
	m := &multipartStrictReaderDecorator{
		reader:   body,
		boundary: "------------------------1aa6ce6559102",
	}

	// Act
	_, err := ioutil.ReadAll(m)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if m.completed() != true {
		t.Fatalf("Got unexpected completed()")
	}

	if m.multipartDataBefore != false {
		t.Fatalf("Got unexpected multipartDataBefore")
	}

	if m.multipartDataAfter != false {
		t.Fatalf("Got unexpected multipartDataAfter")
	}

	if m.multipartHeaderFolding != true {
		t.Fatalf("Got unexpected multipartHeaderFolding")
	}

	if m.multipartLfLine != false {
		t.Fatalf("Got unexpected multipartLfLine")
	}

	if m.multipartInvalidHeaderFolding != false {
		t.Fatalf("Got unexpected multipartInvalidHeaderFolding")
	}

	if m.multipartUnmatchedBoundary != false {
		t.Fatalf("Got unexpected multipartUnmatchedBoundary")
	}
}

func TestReqScannerBodyMultipartStrictHeaderFolding3(t *testing.T) {
	// Arrange
	// The "someheader" is continued on the next line prepended by a \v.
	body := bytes.NewBufferString("--------------------------1aa6ce6559102\r\ncontent-disposition: form-data; name=\"a\"\r\nsomeheader: hello\r\n\vworld\r\n\r\nhelloworld\r\n--------------------------1aa6ce6559102--\r\n")
	m := &multipartStrictReaderDecorator{
		reader:   body,
		boundary: "------------------------1aa6ce6559102",
	}

	// Act
	_, err := ioutil.ReadAll(m)

	// Assert
	if err != nil {
		t.Fatalf("Got unexpected error: %s", err)
	}

	if m.completed() != true {
		t.Fatalf("Got unexpected completed()")
	}

	if m.multipartDataBefore != false {
		t.Fatalf("Got unexpected multipartDataBefore")
	}

	if m.multipartDataAfter != false {
		t.Fatalf("Got unexpected multipartDataAfter")
	}

	if m.multipartHeaderFolding != true {
		t.Fatalf("Got unexpected multipartHeaderFolding")
	}

	if m.multipartLfLine != false {
		t.Fatalf("Got unexpected multipartLfLine")
	}

	if m.multipartInvalidHeaderFolding != true {
		t.Fatalf("Got unexpected multipartInvalidHeaderFolding")
	}

	if m.multipartUnmatchedBoundary != false {
		t.Fatalf("Got unexpected multipartUnmatchedBoundary")
	}
}
