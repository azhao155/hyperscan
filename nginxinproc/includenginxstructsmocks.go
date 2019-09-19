// +build !nginxinproc

package main

/*
// Include very simplified versions of the Nginx structs we are using, just to be able to compile while testing without having an entire built Nginx source tree.
// The resulting binary from this will not be usable for anything except verifying that it could compile.
#cgo CFLAGS: -I${SRCDIR}/nginxstructsmocks
*/
import "C"
