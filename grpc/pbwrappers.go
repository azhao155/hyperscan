package grpc

import (
	pb "azwaf/proto"
	"azwaf/waf"
)

type wafHTTPRequestPbWrapper struct{ pb *pb.WafHttpRequest }

func (r *wafHTTPRequestPbWrapper) Method() string { return r.pb.Method }
func (r *wafHTTPRequestPbWrapper) URI() string    { return r.pb.Uri }
func (r *wafHTTPRequestPbWrapper) Body() []byte   { return r.pb.Body }
func (r *wafHTTPRequestPbWrapper) Headers() []waf.HeaderPair {
	hh := make([]waf.HeaderPair, 0, len(r.pb.Headers))
	for _, ph := range r.pb.Headers {
		hh = append(hh, &headerPairPbWrapper{pb: ph})
	}
	return hh
}

type headerPairPbWrapper struct{ pb *pb.HeaderPair }

func (h *headerPairPbWrapper) Key() string   { return h.pb.Key }
func (h *headerPairPbWrapper) Value() string { return h.pb.Value }
