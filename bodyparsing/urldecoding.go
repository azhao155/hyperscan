package bodyparsing

import (
	"bytes"
	"io"
)

func newURLDecoder(r io.Reader) *urlDecoder {
	return &urlDecoder{
		r:     r,
		state: lookingForEq,
	}
}

type urldecoderState int

const (
	_ urldecoderState = iota
	lookingForEq
	foundEq
	endOfStream
)

type urlDecoder struct {
	r            io.Reader
	buf          bytes.Buffer
	state        urldecoderState
	scannedUntil int
	eqPos        int
}

func (d *urlDecoder) next() (key string, val string, err error) {
	if d.state == endOfStream {
		err = io.EOF
		return
	}

	for {
		bb := d.buf.Bytes()

		for i := d.scannedUntil; i < len(bb); i++ {
			c := bb[i]
			switch d.state {
			case lookingForEq:
				switch c {
				case '=':
					d.eqPos = i
					d.state = foundEq
				case '&':
					// There was no equal-sign in this "pair"
					key = string(bb[:i])
					val = ""

					// Consume number of bytes equivalent to this key-val pair from the buffer.
					d.buf.Next(i + 1)

					d.scannedUntil = 0
					d.eqPos = 0

					return
				}
			case foundEq:
				switch c {
				case '&':
					key = string(bb[:d.eqPos])
					val = string(bb[d.eqPos+1 : i])

					// Consume number of bytes equivalent to this key-val pair from the buffer.
					d.buf.Next(i + 1)

					d.state = lookingForEq
					d.scannedUntil = 0
					d.eqPos = 0

					return
				}
			}
		}

		d.scannedUntil = len(bb)

		// We didn't find a key-val pair in the currently buffered bytes yet, so read some more into our buffer.
		var n int64
		n, err = d.buf.ReadFrom(io.LimitReader(d.r, 1000))
		if err != nil {
			return
		}

		// Was this the end of the stream?
		if n == 0 {
			bb := d.buf.Bytes()

			// If there was no outstanding bytes in the buffer just return EOF.
			if len(bb) == 0 {
				err = io.EOF
			}

			// If we already found an equal-sign, then we have a complete key-val pair.
			if d.state == foundEq {
				key = string(bb[:d.eqPos])
				val = string(bb[d.eqPos+1:])
			} else {
				// We don't have a complete key-val pair, so we decide to just return the remaining bytes as a key with an empty value.
				key = string(bb)
			}

			// Consume the rest of the buffer, just to leave things in a consistent state.
			d.buf.Next(len(bb))

			d.state = endOfStream

			return
		}
	}
}
