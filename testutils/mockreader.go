package testutils

import (
	"io"
)

// MockReader is an io.Reader implementation that that fills up the given buffer with copies of the Content byte slice until Length is reached.
type MockReader struct {
	Pos     int
	Length  int
	Content []byte
	next    []byte
}

// Read Fills up the given buffer with 'a'-chars on each call until Length is reached.
func (m *MockReader) Read(p []byte) (n int, err error) {
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
