package main

/*
 *
 * Used by the Nginx module that runs Azwaf in-proc within an Nginx worker, as opposed to running as a standalone process connected via gRPC.
 *
 * Compile the C part into your Nginx by adding this to your Nginx configure-line:
 *   --add-module=/home/youruser/azwaf/nginxinproc/nginx-azwaf
 *
 * Compile Azwaf as a C shared library:
 *   ./buildazwafnginxinprocso.sh /path/to/nginxsourcetree
 *
 * The C code uses dlsym to load at runtime in the Nginx worker, rather than statically or dynamically linking.
 * The reason for this is a workaround for an issue with Nginx working together with CGo.
 * Details can be found in the issues section here: https://github.com/robinmonjo/ngx_http_l
 *
 */

/*
#include <ngx_http.h>
#include "bodyreading.h"
*/
import "C"

import (
	sreng "azwaf/secrule/engine"
	srrs "azwaf/secrule/reqscanning"
	srre "azwaf/secrule/ruleevaluation"
	srrp "azwaf/secrule/ruleparsing"

	"azwaf/bodyparsing"
	"azwaf/hyperscan"
	"azwaf/logging"
	"azwaf/waf"
	"io"
	"os"
	"reflect"
	"time"
	"unsafe"

	"github.com/rs/zerolog"
)

// AzwafEvalRequest is the interface to the rest of Azwaf called from the in-proc Nginx plugin.
//export AzwafEvalRequest
func AzwafEvalRequest(requestID C.ngx_str_t, secruleconfngx C.ngx_str_t, input *C.ngx_http_request_t, ngxReadFileCb C.ngxReadFileFn) bool {
	instance := getInstance(ngxStrToGoStr(secruleconfngx))

	req := newNginxReqWrapper(requestID, input, ngxReadFileCb)

	decision, err := instance.EvalRequest(req)
	if err != nil {
		logger.Warn().Err(err).Msg("Error from s.ws.EvalRequest(w)")
		return false
	}

	return decision != waf.Block
}

// TODO Having a separate object tree here is a very memory-ineffecient way of having multiple configs. Most objects could be shared.
var nginxWafInstances map[string]*waf.Server = make(map[string]*waf.Server)
var loggerInitialized bool
var logger zerolog.Logger

func getInstance(secruleconf string) waf.Server {
	if instance, ok := nginxWafInstances[secruleconf]; ok {
		return *instance
	}

	if loggerInitialized == false {
		loglevel := zerolog.FatalLevel
		logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).Level(loglevel).With().Timestamp().Caller().Logger()
		loggerInitialized = true
	}

	// Initialize common dependencies

	// TODO implement log file reopening ability.
	reopenLogFileChan := make(chan bool)
	rlf, err := logging.NewFileLogResultsLoggerFactory(&logging.LogFileSystemImpl{}, logger, reopenLogFileChan, logging.FileName)
	if err != nil {
		logger.Fatal().Err(err).Msg("Error while creating file logger")
	}

	rbp := bodyparsing.NewRequestBodyParser(waf.DefaultLengthLimits)
	p := srrp.NewRuleParser()
	rlfs := srrp.NewRuleLoaderFileSystem()
	hsfs := hyperscan.NewCacheFileSystem()
	hscache := hyperscan.NewDbCache(hsfs)
	mref := hyperscan.NewMultiRegexEngineFactory(hscache)
	rsf := srrs.NewReqScannerFactory(mref)
	ref := srre.NewRuleEvaluatorFactory()

	srl := srrp.NewStandaloneRuleLoader(p, rlfs, secruleconf)
	stmts, err := srl.Rules()
	if err != nil {
		logger.Fatal().Err(err).Msg("Error while loading rules")
	}

	sre, err := sreng.NewEngine(stmts, rsf, ref, "", nil)
	if err != nil {
		logger.Fatal().Err(err).Msg("Error while creating SecRule engine")
	}

	instance, err := waf.NewStandaloneSecruleServer(logger, rlf, sre, rbp)
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
func newNginxReqWrapper(requestID C.ngx_str_t, input *C.ngx_http_request_t, ngxReadFileCb C.ngxReadFileFn) waf.HTTPRequest {
	req := &nginxReqWrapper{
		underlyingNgxReq: input,
		method:           ngxStrToGoStr(input.method_name),
		uri:              ngxStrToGoStr(input.unparsed_uri),
		protocol:         ngxStrToGoStr(input.http_protocol),
		bodyReader: bodyReader{
			underlyingNgxReq: input,
			ngxReadFileCb:    ngxReadFileCb,
		},
		transactionID: ngxStrToGoStr(requestID),
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
	uri           string
	method        string
	protocol      string
	headers       []waf.HeaderPair
	transactionID string
}

func (r *nginxReqWrapper) Method() string            { return r.method }
func (r *nginxReqWrapper) URI() string               { return r.uri }
func (r *nginxReqWrapper) Protocol() string          { return r.protocol }
func (r *nginxReqWrapper) Headers() []waf.HeaderPair { return r.headers }
func (r *nginxReqWrapper) ConfigID() string          { return "" }
func (r *nginxReqWrapper) BodyReader() io.Reader {
	return &r.bodyReader
}
func (r *nginxReqWrapper) LogMetaData() waf.RequestLogMetaData { return nil }
func (r *nginxReqWrapper) TransactionID() string               { return r.transactionID }
func (r *nginxReqWrapper) RemoteAddr() string                  { return "" }

type headerPair struct {
	k string
	v string
}

func (h *headerPair) Key() string   { return h.k }
func (h *headerPair) Value() string { return h.v }

func main() {}
