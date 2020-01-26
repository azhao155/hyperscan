package encoding

import (
	"azwaf/testutils"
	"bytes"
	"io"
	"testing"
)

func TestUrldecoder1(t *testing.T) {
	// Arrange
	body := bytes.NewBufferString("abc=def&&ghi=jkl=mno&pqr&=stu&hello=world&hello=world2")
	d := NewURLDecoder(body)

	type expectCase struct {
		key string
		val string
		err error
	}
	expected := []expectCase{
		{"abc", "def", nil},
		{"", "", nil},
		{"ghi", "jkl=mno", nil},
		{"pqr", "", nil},
		{"", "stu", nil},
		{"hello", "world", nil},
		{"hello", "world2", nil},
		{"", "", io.EOF},
	}

	// Act and assert
	for i, e := range expected {
		k, v, err := d.Next()
		if k != e.key {
			t.Fatalf("Unexpected key %v: %v", i, k)
		}
		if v != e.val {
			t.Fatalf("Unexpected val %v: %v", i, v)
		}
		if err != e.err {
			t.Fatalf("Unexpected err %v %T: %v", i, err, err)
		}
	}
}

func TestUrldecoderManyPairs(t *testing.T) {
	// Arrange
	bb := []byte("hello=world123&")
	body1 := &testutils.MockReader{Length: 1000 * len(bb), Content: bb}
	body2 := bytes.NewBufferString("a=b")
	body := io.MultiReader(body1, body2)
	d := NewURLDecoder(body)

	// Act and assert
	for i := 0; i < 1000; i++ {
		k, v, err := d.Next()
		if k != "hello" {
			t.Fatalf("Unexpected key %v", i)
		}
		if v != "world123" {
			t.Fatalf("Unexpected val %v", i)
		}
		if err != nil {
			t.Fatalf("Unexpected err %v %T: %v", i, err, err)
		}
	}

	k2, v2, err2 := d.Next()
	_, _, err3 := d.Next()

	if err2 != nil {
		t.Fatalf("Unexpected err %T: %v", err2, err2)
	}

	if err3 != io.EOF {
		t.Fatalf("Unexpected err %T: %v", err3, err3)
	}

	if k2 != "a" {
		t.Fatalf("Unexpected key1")
	}

	if v2 != "b" {
		t.Fatalf("Unexpected val2")
	}
}

func TestUrldecoderStrangeStart(t *testing.T) {
	// Arrange
	body := bytes.NewBufferString("a&b=c")
	d := NewURLDecoder(body)

	type expectCase struct {
		key string
		val string
		err error
	}
	expected := []expectCase{
		{"a", "", nil},
		{"b", "c", nil},
		{"", "", io.EOF},
	}

	// Act and assert
	for i, e := range expected {
		k, v, err := d.Next()
		if k != e.key {
			t.Fatalf("Unexpected key %v: %v", i, k)
		}
		if v != e.val {
			t.Fatalf("Unexpected val %v: %v", i, v)
		}
		if err != e.err {
			t.Fatalf("Unexpected err %v %T: %v", i, err, err)
		}
	}
}

func TestUrldecoderLongVal(t *testing.T) {
	// Arrange
	body1 := bytes.NewBufferString("a=")
	body2 := &testutils.MockReader{Length: 1024 * 256, Content: []byte("b")}
	body := io.MultiReader(body1, body2)
	d := NewURLDecoder(body)

	// Act
	k1, v1, err1 := d.Next()
	_, _, err2 := d.Next()

	// Assert
	if err1 != nil {
		t.Fatalf("Unexpected err %T: %v", err1, err1)
	}

	if err2 != io.EOF {
		t.Fatalf("Unexpected err %T: %v", err2, err2)
	}

	if k1 != "a" {
		t.Fatalf("Unexpected key")
	}

	if len(v1) != 1024*256 {
		t.Fatalf("Unexpected len(val): %v", len(v1))
	}
}

func TestUrldecoderLongValWithTrailingPair(t *testing.T) {
	// Arrange
	body1 := bytes.NewBufferString("a=")
	body2 := &testutils.MockReader{Length: 1024 * 256, Content: []byte("b")}
	body3 := bytes.NewBufferString("&c=d")
	body := io.MultiReader(body1, body2, body3)
	d := NewURLDecoder(body)

	// Act
	k1, v1, err1 := d.Next()
	k2, v2, err2 := d.Next()
	_, _, err3 := d.Next()

	// Assert
	if err1 != nil {
		t.Fatalf("Unexpected err %T: %v", err1, err1)
	}

	if err2 != nil {
		t.Fatalf("Unexpected err %T: %v", err2, err2)
	}

	if err3 != io.EOF {
		t.Fatalf("Unexpected err %T: %v", err3, err3)
	}

	if k1 != "a" {
		t.Fatalf("Unexpected key1")
	}

	if len(v1) != 1024*256 {
		t.Fatalf("Unexpected len(val1): %v", len(v1))
	}

	if k2 != "c" {
		t.Fatalf("Unexpected key2")
	}

	if v2 != "d" {
		t.Fatalf("Unexpected val2")
	}
}

func TestUrldecoderLongKey(t *testing.T) {
	// Arrange
	body1 := &testutils.MockReader{Length: 1024 * 256, Content: []byte("a")}
	body2 := bytes.NewBufferString("=b&c=d")
	body := io.MultiReader(body1, body2)
	d := NewURLDecoder(body)

	// Act
	k1, v1, err1 := d.Next()
	k2, v2, err2 := d.Next()
	_, _, err3 := d.Next()

	// Assert
	if err1 != nil {
		t.Fatalf("Unexpected err %T: %v", err1, err1)
	}

	if err2 != nil {
		t.Fatalf("Unexpected err %T: %v", err2, err2)
	}

	if err3 != io.EOF {
		t.Fatalf("Unexpected err %T: %v", err3, err3)
	}

	if len(k1) != 1024*256 {
		t.Fatalf("Unexpected len(key): %v", len(k1))
	}

	if v1 != "b" {
		t.Fatalf("Unexpected val1")
	}

	if k2 != "c" {
		t.Fatalf("Unexpected key2")
	}

	if v2 != "d" {
		t.Fatalf("Unexpected val2")
	}
}
