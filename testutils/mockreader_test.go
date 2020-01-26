package testutils

import (
	"bytes"
	"testing"
)

// Tests that the MockReader works, which itself is just used for other tests.
func TestMockReader(t *testing.T) {
	// Arrange
	content := []byte("hello,")
	targetLen := 1024 * 1024 * 2
	m := &MockReader{Length: targetLen, Content: content}
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
