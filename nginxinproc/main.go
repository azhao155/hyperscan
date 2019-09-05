// +build nginxinproc

package main

/*
 *
 * Used by the Nginx module that runs Azwaf in-proc within an Nginx worker, as opposed to running as a standalone process connected via gRPC.
 *
 * Compile the Azwaf as a C shared library like this:
 *   go build -tags=nginxinproc -buildmode=c-shared -o azwafnginxinproc.so azwaf/nginxinproc
 *
 * Compile the C part into your Nginx by adding this to your Nginx configure-line:
 *   --add-module=/home/youruser/azwaf/nginxinproc/nginx-azwaf
 *
 * This code uses dlsym to load at runtime in the Nginx worker, rather than statically or dynamically linking.
 * The reason for this is a workaround for an issue with Nginx working together with CGo.
 * Details can be found in the issues section here: https://github.com/robinmonjo/ngx_http_l
 *
 */

/*
#cgo CFLAGS: -I${SRCDIR}/../../nginx/src/core
#cgo CFLAGS: -I${SRCDIR}/../../nginx/src/http
#cgo CFLAGS: -I${SRCDIR}/../../nginx/objs
#cgo CFLAGS: -I${SRCDIR}/../../nginx/src/os/unix
#cgo CFLAGS: -I${SRCDIR}/../../nginx/src/event
#cgo CFLAGS: -I${SRCDIR}/../../nginx/src/http/v2
#cgo CFLAGS: -I${SRCDIR}/../../nginx/src/http/modules
#include <ngx_http.h>
#include "bodyreading.h"
*/
import "C"

import (
	"azwaf/bodyparsing"
	"azwaf/hyperscan"
	"azwaf/logging"
	"azwaf/secrule"
	"azwaf/waf"
	"github.com/rs/zerolog"
	"io"
	"os"
	"reflect"
	"time"
	"unsafe"
)

var lengthLimits = waf.LengthLimits{
	MaxLengthField:    1024 * 20,         // 20 KiB
	MaxLengthPausable: 1024 * 128,        // 128 KiB
	MaxLengthTotal:    1024 * 1024 * 700, // 700 MiB
}

// AzwafEvalRequest is the interface to the rest of Azwaf called from the in-proc Nginx plugin.
//export AzwafEvalRequest
func AzwafEvalRequest(secruleconfngx C.ngx_str_t, input *C.ngx_http_request_t, ngxReadFileCb C.ngxReadFileFn) bool {
	instance := getInstance(ngxStrToGoStr(secruleconfngx))

	req := newNginxReqWrapper(input, ngxReadFileCb)

	allow, err := instance.EvalRequest(req)
	if err != nil {
		return false
	}

	return allow
}

// TODO Having a separate object tree here is a very memory-ineffecient way of having multiple configs. Most objects could be shared.
var nginxWafInstances map[string]*waf.Server = make(map[string]*waf.Server)

func getInstance(secruleconf string) waf.Server {
	if instance, ok := nginxWafInstances[secruleconf]; ok {
		return *instance
	}

	// Initialize common dependencies
	loglevel := zerolog.Disabled
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).Level(loglevel).With().Timestamp().Caller().Logger()
	secruleResLog, wafResLog := logging.NewZerologResultsLogger(logger)
	rbp := bodyparsing.NewRequestBodyParser(lengthLimits)
	p := secrule.NewRuleParser()
	rlfs := secrule.NewRuleLoaderFileSystem()
	hsfs := hyperscan.NewCacheFileSystem()
	hscache := hyperscan.NewDbCache(hsfs)
	mref := hyperscan.NewMultiRegexEngineFactory(hscache)
	rsf := secrule.NewReqScannerFactory(mref)
	re := secrule.NewRuleEvaluator()

	srl := secrule.NewStandaloneRuleLoader(p, rlfs, secruleconf)
	stmts, err := srl.Rules()
	if err != nil {
		logger.Fatal().Err(err).Msg("Error while loading rules")
	}

	sre, err := secrule.NewEngine(stmts, rsf, re, secruleResLog)
	if err != nil {
		logger.Fatal().Err(err).Msg("Error while creating SecRule engine")
	}

	instance, err := waf.NewStandaloneSecruleServer(logger, sre, rbp, wafResLog)
	if err != nil {
		logger.Fatal().Err(err).Msg("Error while creating standalone SecRule engine WAF")
	}

	nginxWafInstances[secruleconf] = &instance
	return instance
}

// Create a Go-string whose underlying memory uses point to the original memory allocated by Nginx.
func ngxStrToGoStr(s C.ngx_str_t) string {
	sh := reflect.StringHeader{uintptr(unsafe.Pointer(s.data)), int(s.len)}
	return *(*string)(unsafe.Pointer(&sh))
}

// newNginxReqWrapper creates an Azwaf Azwaf waf.HTTPRequest that wraps an Nginx request struct.
func newNginxReqWrapper(input *C.ngx_http_request_t, ngxReadFileCb C.ngxReadFileFn) waf.HTTPRequest {
	req := &nginxReqWrapper{
		underlyingNgxReq: input,
		method:           ngxStrToGoStr(input.method_name),
		uri:              ngxStrToGoStr(input.unparsed_uri),
		bodyReader: bodyReader{
			underlyingNgxReq: input,
			ngxReadFileCb:    ngxReadFileCb,
		},
	}

	// Make ngxStrToGoStr-versions of each header
	var part *C.ngx_list_part_t
	part = &(input.headers_in.headers.part)
	for part != nil {
		for i := 0; i < int(part.nelts); i++ {
			// Calculate a pointer the header element by adding the size of a header element to the last current pointer.
			var elt *C.ngx_table_elt_t
			elt = (*C.ngx_table_elt_t)(unsafe.Pointer(uintptr(part.elts) + C.sizeof_ngx_table_elt_t*uintptr(i)))

			k := ngxStrToGoStr(elt.key)
			v := ngxStrToGoStr(elt.value)
			req.headers = append(req.headers, &headerPair{k: k, v: v})
		}

		// Traverse to the next linked list element.
		part = part.next
	}

	return req
}

type nginxReqWrapper struct {
	underlyingNgxReq *C.ngx_http_request_t
	bodyReader       bodyReader

	// Storing as strings rather than using underlyingNgxReq for each of these, in order to avoid having to recreate string headers in ngxStrToGoStr every time a value is needed.
	// Because string headers are used in ngxStrToGoStr, the underlying memory for the strings actually still point to the original memory allocated by Nginx.
	uri     string
	method  string
	headers []waf.HeaderPair
}

func (r *nginxReqWrapper) Method() string            { return r.method }
func (r *nginxReqWrapper) URI() string               { return r.uri }
func (r *nginxReqWrapper) Headers() []waf.HeaderPair { return r.headers }
func (r *nginxReqWrapper) ConfigID() string          { return "" }
func (r *nginxReqWrapper) BodyReader() io.Reader {
	return &r.bodyReader
}

type headerPair struct {
	k string
	v string
}

func (h *headerPair) Key() string   { return h.k }
func (h *headerPair) Value() string { return h.v }

func main() {}
