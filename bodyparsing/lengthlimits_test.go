package bodyparsing

import (
	"azwaf/waf"
	"bytes"
	"strings"
	"testing"
)

func TestMaxLengthReader(t *testing.T) {
	// Arrange
	readerBuf := bytes.NewBufferString(strings.Repeat("aaaaaaaaaa", 10000))
	tmp := make([]byte, 1000)
	m := newMaxLengthReaderDecorator(readerBuf, waf.LengthLimits{15000, 20000, 100000})

	// Act
	n := 0
	var err error
	for {
		var n2 int
		n2, err = m.Read(tmp)
		n += n2
		if err != nil {
			break
		}

		m.ResetFieldReadCount()
	}

	// Assert
	if err != waf.ErrPausableBytesLimitExceeded {
		t.Fatalf("Expected errPausableBytesLimitExceeded error, but got: %v", err)
	}

	if n < 20000 {
		t.Fatalf("Read less bytes than expected from maxLengthReaderDecorator. Only read %v bytes.", n)
	}
}

func TestMaxLengthReaderFieldLimit(t *testing.T) {
	// Arrange
	readerBuf := bytes.NewBufferString(strings.Repeat("aaaaaaaaaa", 10000))
	tmp := make([]byte, 1000)
	m := newMaxLengthReaderDecorator(readerBuf, waf.LengthLimits{15000, 20000, 100000})

	// Act
	n := 0
	var err error
	for i := 0; i < 500; i++ {
		var n2 int
		n2, err = m.Read(tmp)
		n += n2
		if err != nil {
			break
		}

		// Note we are not calling m.ResetFieldReadCount() for this test case
	}

	// Assert
	if err != waf.ErrFieldBytesLimitExceeded {
		t.Fatalf("Expected errFieldBytesLimitExceeded error, but got: %v", err)
	}

	if n < 15000 {
		t.Fatalf("Read less bytes than expected from maxLengthReaderDecorator. Only read %v bytes.", n)
	}
}

func TestMaxLengthReaderWithPause(t *testing.T) {
	// Arrange
	readerBuf := bytes.NewBufferString(strings.Repeat("aaaaaaaaaa", 10000))
	tmp := make([]byte, 1000)
	m := newMaxLengthReaderDecorator(readerBuf, waf.LengthLimits{15000, 20000, 100000})

	// Act and assert
	for i := 0; i < 5; i++ {
		_, err := m.Read(tmp)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	}
	m.PauseCounting = true
	for i := 0; i < 50; i++ {
		_, err := m.Read(tmp)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	}
	m.PauseCounting = false
	for i := 0; i < 5; i++ {
		_, err := m.Read(tmp)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	}
}

func TestMaxLengthReaderTotalLimit(t *testing.T) {
	// Arrange
	readerBuf := bytes.NewBufferString(strings.Repeat("aaaaaaaaaa", 20000))
	tmp := make([]byte, 1000)
	m := newMaxLengthReaderDecorator(readerBuf, waf.LengthLimits{15000, 20000, 100000})

	// Act and assert
	n := 0
	for i := 0; i < 5; i++ {
		n2, err := m.Read(tmp)
		n += n2
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	}
	m.PauseCounting = true

	var err error
	for i := 0; i < 1000; i++ {
		var n2 int
		n2, err = m.Read(tmp)
		n += n2
		if err != nil {
			break
		}
	}

	// Assert
	if err != waf.ErrTotalBytesLimitExceeded {
		t.Fatalf("Expected errFieldBytesLimitExceeded error, but got: %v", err)
	}

	if n < 100000 {
		t.Fatalf("Read less bytes than expected from maxLengthReaderDecorator. Only read %v bytes.", n)
	}
}
