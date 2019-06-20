package libinjection

/*
#include "libinjection.h"
#include "libinjection_sqli.h"
*/
import "C"
import (
	"bytes"
	"unsafe"
)

// IsSQLi evaluates input for SQL injection attack
func IsSQLi(input string) (bool, string) {
	var out [8]C.char
	fingerprint := (*C.char)(unsafe.Pointer(&out[0]))

	if found := C.libinjection_sqli(C.CString(input), C.size_t(len(input)), fingerprint); found == 1 {
		output := C.GoBytes(unsafe.Pointer(&out[0]), 8)
		return true, string(output[:bytes.Index(output, []byte{0})])
	}

	return false, ""
}

// IsXSS evaluates input for XSS attack
func IsXSS(input string) bool {
	if found := C.libinjection_xss(C.CString(input), C.size_t(len(input))); found == 1 {
		return true
	}
	return false
}
