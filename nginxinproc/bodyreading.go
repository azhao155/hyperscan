// +build nginxinproc

package main

/*
#include <ngx_http.h>
#include "bodyreading.h"

// Go does not seem to support directly invoking C function pointers. Therefore this wrapper.
static inline ssize_t invokeNgxReadFileCb(ngxReadFileFn ngxReadFileCb, ngx_file_t *file, u_char *buf, size_t size, off_t offset) {
	return ngxReadFileCb(file, buf, size, offset);
}
*/
import "C"

import (
	"fmt"
	"io"
	"reflect"
	"unsafe"
)

type bodyReader struct {
	underlyingNgxReq *C.ngx_http_request_t
	ngxReadFileCb    C.ngxReadFileFn
	curInMemChain    *C.ngx_chain_t
	curInMemBufPos   int
	bodyFilePos      int
}

func (b *bodyReader) Read(p []byte) (n int, err error) {
	r := b.underlyingNgxReq

	if r.request_body == nil {
		// This probably never happens. Nginx usually always populates this field, but will leave both temp_file and bufs as null if there was no request body.
		err = io.EOF
		return
	}

	if r.request_body.temp_file != nil {
		// Let ngx_read_file write data directly into p
		var file *C.ngx_file_t = &(r.request_body.temp_file.file)
		ret := (int)(C.invokeNgxReadFileCb(b.ngxReadFileCb, file, (*C.uchar)(unsafe.Pointer(&p[0])), (C.ulong)(len(p)), (C.long)(b.bodyFilePos)))
		if ret > 0 {
			n = ret
			b.bodyFilePos += ret
			if n < len(p) {
				err = io.EOF
			}
		} else if ret == 0 {
			err = io.EOF
		} else {
			err = fmt.Errorf("error code %d while reading Nginx request body", ret)
		}
	} else if r.request_body.bufs != nil {
		if b.curInMemChain == nil {
			b.curInMemChain = r.request_body.bufs
		}

		// Wrap the Nginx buffer struct in a Go byte-slice header, so we can treat it as a Go byte-slice.
		buflen := int(uintptr(unsafe.Pointer(b.curInMemChain.buf.last)) - uintptr(unsafe.Pointer(b.curInMemChain.buf.pos)))
		sh := reflect.SliceHeader{uintptr(unsafe.Pointer(b.curInMemChain.buf.pos)), buflen, buflen}
		bb := *(*[]byte)(unsafe.Pointer(&sh))

		// Do the actual copy from the Nginx buffer to the io.Reader p output variable.
		remainingInCurBuf := bb[b.curInMemBufPos:]
		n = copy(p, remainingInCurBuf)
		b.curInMemBufPos += n

		// Are we done copying out the current ngx_chain_t buffer?
		if b.curInMemBufPos == buflen {
			b.curInMemBufPos = 0
			b.curInMemChain = b.curInMemChain.next

			// If there was no next buffer in the ngx_chain_t, then we are done.
			if b.curInMemChain == nil {
				err = io.EOF
			}
		}
	} else {
		// There was no request body. For example a GET request.
		err = io.EOF
	}

	return
}
