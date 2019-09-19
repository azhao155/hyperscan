// +build nginxinproc

package main

/*
// To build a usable .so, there needs to be a symlink /tmp/azwafnginx/ pointing to the Nginx source tree path you are building for
#cgo CFLAGS: -I/tmp/azwafnginx/src/core
#cgo CFLAGS: -I/tmp/azwafnginx/src/http
#cgo CFLAGS: -I/tmp/azwafnginx/objs
#cgo CFLAGS: -I/tmp/azwafnginx/src/os/unix
#cgo CFLAGS: -I/tmp/azwafnginx/src/event
#cgo CFLAGS: -I/tmp/azwafnginx/src/http/v2
#cgo CFLAGS: -I/tmp/azwafnginx/src/http/modules
*/
import "C"
