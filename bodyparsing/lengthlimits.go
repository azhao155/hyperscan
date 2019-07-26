package bodyparsing

import (
	"azwaf/waf"
	"io"
)

// maxLengthReaderDecorator is an io.Reader decorator, which enforces a max number of bytes to be read.
type maxLengthReaderDecorator struct {
	PauseCounting     bool
	Limits            waf.LengthLimits
	ReadCountField    int
	ReadCountPausable int
	ReadCountTotal    int
	LastErr           error
	reader            io.Reader
}

func newMaxLengthReaderDecorator(reader io.Reader, limits waf.LengthLimits) *maxLengthReaderDecorator {
	return &maxLengthReaderDecorator{reader: reader, Limits: limits}
}

// Read behaves like io.Reader.Read, but returns errors on the call after the call where the max number of bytes was exceeded.
// If the PauseCounting flag is set, the bytes read is not counted.
func (m *maxLengthReaderDecorator) Read(p []byte) (n int, err error) {
	defer func() {
		if err != nil {
			m.LastErr = err
		}
	}()

	if m.ReadCountTotal >= m.Limits.MaxLengthTotal {
		err = waf.ErrTotalBytesLimitExceeded
		return
	}

	if m.ReadCountPausable >= m.Limits.MaxLengthPausable {
		err = waf.ErrPausableBytesLimitExceeded
		return
	}

	if m.ReadCountField >= m.Limits.MaxLengthField {
		err = waf.ErrFieldBytesLimitExceeded
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
