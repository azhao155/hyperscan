package secrule

import (
	"errors"
	"io"
)

// LengthLimits states limitations we will enforce regarding the lengths of different parts of the request.
type LengthLimits struct {
	MaxLengthField    int // Number of bytes read before returning an error, respecting the PauseCounting flag. The count can be reset whenever a field has been consumed .
	MaxLengthPausable int // Number of bytes read before returning an error, respecting the PauseCounting flag.
	MaxLengthTotal    int // Number of bytes read, ignoring whether the PauseCounting flag was set.
}

// maxLengthReaderDecorator is an io.Reader decorator, which enforces a max number of bytes to be read.
type maxLengthReaderDecorator struct {
	PauseCounting     bool
	Limits            LengthLimits
	ReadCountField    int
	ReadCountPausable int
	ReadCountTotal    int
	reader            io.Reader
}

func newMaxLengthReaderDecorator(reader io.Reader, limits LengthLimits) *maxLengthReaderDecorator {
	return &maxLengthReaderDecorator{reader: reader, Limits: limits}
}

//maxLengthReaderFieldLimitExceeded
var errFieldBytesLimitExceeded = errors.New("field length limit exceeded")
var errPausableBytesLimitExceeded = errors.New("request length limit exceeded")
var errTotalBytesLimitExceeded = errors.New("total request length limit exceeded")

// Read behaves like io.Reader.Read, but returns errors on the call after the call where the max number of bytes was exceeded.
// If the PauseCounting flag is set, the bytes read is not counted.
func (m *maxLengthReaderDecorator) Read(p []byte) (n int, err error) {
	if m.IsTotalLimitReached() {
		err = errTotalBytesLimitExceeded
		return
	}

	if m.IsPausableReached() {
		err = errPausableBytesLimitExceeded
		return
	}

	if m.IsFieldLimitReached() {
		err = errFieldBytesLimitExceeded
		return
	}

	n, err = m.reader.Read(p)
	if n > 0 {
		if !m.PauseCounting {
			m.ReadCountPausable += n
			m.ReadCountField += n
		}

		m.ReadCountTotal += n
	}

	return
}

// ResetFieldReadCount is meant to be called before starting to read a field. It resets the count of many bytes was read for the current field.
func (m *maxLengthReaderDecorator) ResetFieldReadCount() {
	m.ReadCountField = 0
}

// IsFieldLimitReached tells whether the limit of the current field being read was reached, taking PauseCounting into account.
func (m *maxLengthReaderDecorator) IsFieldLimitReached() bool {
	return m.ReadCountField >= m.Limits.MaxLengthField
}

// IsPausableReached tells whether the limit is reached, taking PauseCounting into account.
func (m *maxLengthReaderDecorator) IsPausableReached() bool {
	return m.ReadCountPausable >= m.Limits.MaxLengthPausable
}

// IsTotalLimitReached tells whether the total limit is reached, ignoring the count of bytes read while PauseCounting was true.
func (m *maxLengthReaderDecorator) IsTotalLimitReached() bool {
	return m.ReadCountTotal >= m.Limits.MaxLengthTotal
}
