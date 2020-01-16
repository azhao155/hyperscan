package bodyparsing

import (
	"io"
)

type multipartStrictReaderState int

// States for the state machine below
const (
	beforeBoundary multipartStrictReaderState = iota
	afterBoundaryDash1
	afterBoundaryDash2
	afterBoundaryCr
	beforeHeaderStarted
	afterHeaderCr
	afterEmptyHeaderCr
	afterHeaderStarted
	afterFinalBoundaryFinalDash1
	afterFinalBoundaryFinalDash2
	afterFinalBoundaryCr
	afterFinalBoundaryLf
)

type multipartStrictReaderDecorator struct {
	reader                        io.Reader
	boundary                      string
	boundaryPos                   int
	boundariesSeen                int
	state                         multipartStrictReaderState
	multipartDataAfter            bool
	multipartDataBefore           bool
	multipartHeaderFolding        bool
	multipartInvalidHeaderFolding bool
	multipartLfLine               bool
	multipartUnmatchedBoundary    bool
}

func (m *multipartStrictReaderDecorator) Read(p []byte) (n int, errOut error) {
	n, errOut = m.reader.Read(p)

	for i := 0; i < n; i++ {
		c := p[i]
		switch m.state {

		case beforeBoundary:
			if c == '-' {
				m.state = afterBoundaryDash1
				continue
			}

			if m.boundariesSeen == 0 {
				m.multipartDataBefore = true
			}

		case afterBoundaryDash1:
			if c == '-' {
				m.state = afterBoundaryDash2
				m.boundaryPos = 0
				continue
			}

			if m.boundariesSeen == 0 {
				m.multipartDataBefore = true
				m.state = beforeBoundary
			}

		case afterBoundaryDash2:
			if m.boundaryPos == len(m.boundary) {
				if c == '\r' {
					m.state = afterBoundaryCr
				} else if c == '\n' {
					m.boundariesSeen++
					m.multipartLfLine = true
					m.state = beforeHeaderStarted
				} else if c == '-' {
					m.state = afterFinalBoundaryFinalDash1
				} else {
					m.multipartUnmatchedBoundary = true
					if m.boundariesSeen == 0 {
						m.multipartDataBefore = true
					}
					m.state = beforeBoundary
				}
			} else {
				// Is the boundary diverging from the expected boundary string?
				if c != m.boundary[m.boundaryPos] {
					m.multipartUnmatchedBoundary = true
					if m.boundariesSeen == 0 {
						m.multipartDataBefore = true
					}
					m.state = beforeBoundary
				}
				m.boundaryPos++
			}

		case afterBoundaryCr:
			if c == '\n' {
				m.boundariesSeen++
				m.state = beforeHeaderStarted
			} else {
				m.multipartUnmatchedBoundary = true
				if m.boundariesSeen == 0 {
					m.multipartDataBefore = true
				}
				m.state = beforeBoundary
			}

		case beforeHeaderStarted:
			if c == '\r' {
				m.state = afterEmptyHeaderCr
			} else if c == '\n' {
				m.multipartLfLine = true
				m.state = beforeBoundary
			} else if c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r' {
				m.multipartHeaderFolding = true
				if c != ' ' && c != '\t' {
					m.multipartInvalidHeaderFolding = true
				}
				m.state = afterHeaderStarted
			} else {
				m.state = afterHeaderStarted
			}

		case afterHeaderStarted:
			if c == '\r' {
				m.state = afterHeaderCr
			} else if c == '\n' {
				m.multipartLfLine = true
				m.state = beforeHeaderStarted
			}

		case afterHeaderCr:
			if c == '\n' {
				m.state = beforeHeaderStarted
			} else {
				// We saw a CR without an LF. Guess we are still in the headers.
				m.multipartLfLine = true
				m.state = afterHeaderStarted
			}

		case afterEmptyHeaderCr:
			if c == '\n' {
				// We saw an empty header followed by "\r\n". This means end of headers and next byte is start of content.
				m.state = beforeBoundary
			} else {
				// We saw a CR without an LF. Guess we are still in the headers.
				m.multipartLfLine = true
				m.state = afterHeaderStarted
			}

		case afterFinalBoundaryFinalDash1:
			if c == '-' {
				m.state = afterFinalBoundaryFinalDash2
			} else {
				m.multipartUnmatchedBoundary = true
				if m.boundariesSeen == 0 {
					m.multipartDataBefore = true
				}
				m.state = beforeBoundary
			}

		case afterFinalBoundaryFinalDash2:
			if c == '\r' {
				m.state = afterFinalBoundaryCr
			} else if c == '\n' {
				m.multipartLfLine = true
				m.state = afterFinalBoundaryLf
			} else {
				m.multipartUnmatchedBoundary = true
				if m.boundariesSeen == 0 {
					m.multipartDataBefore = true
				}
				m.state = beforeBoundary
			}

		case afterFinalBoundaryCr:
			if c == '\n' {
				m.state = afterFinalBoundaryLf
			} else {
				m.multipartUnmatchedBoundary = true
				if m.boundariesSeen == 0 {
					m.multipartDataBefore = true
				}
				m.state = beforeBoundary
			}

		case afterFinalBoundaryLf:
			m.multipartDataAfter = true

		}
	}

	return
}

func (m *multipartStrictReaderDecorator) completed() bool {
	return m.state == afterFinalBoundaryLf
}
