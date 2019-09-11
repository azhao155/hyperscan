package grpc

import (
	pb "azwaf/proto"
	"azwaf/waf"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"

	"github.com/rs/zerolog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// Server is an AzWaf gRPC server.
type Server interface {
	Serve() error
}

type serverImpl struct {
	logger zerolog.Logger
	ws     waf.Server
}

// NewServer creates a new AzWaf gRPC server.
func NewServer(logger zerolog.Logger, ws waf.Server) Server {
	return &serverImpl{
		logger: logger,
		ws:     ws,
	}
}

func (s *serverImpl) EvalRequest(stream pb.WafService_EvalRequestServer) error {
	allow := true

	r, err := stream.Recv()
	if err != nil {
		stream.SendAndClose(&pb.WafDecision{Allow: false})
		s.logger.Warn().Err(err).Msg("Error from stream.Recv()")
		return err
	}

	// First message has to be of type HeadersAndFirstChunk
	m, ok := r.Content.(*pb.WafHttpRequest_HeadersAndFirstChunk)
	if !ok {
		stream.SendAndClose(&pb.WafDecision{Allow: false})
		err = fmt.Errorf("first gRPC stream message was not HeadersAndFirstChunk")
		s.logger.Warn().Msg(err.Error())
		return err
	}

	// A callback used to get the rest of the body chunks that we'll get from the gRPC stream
	var buf bytes.Buffer // We need a buffer here, because the io.Reader-client can ask for any arbitrary number of bytes, which will not necessarily align with the sizes of the gRPC messages.
	if m.HeadersAndFirstChunk.FirstBodyChunk != nil {
		buf.Write(m.HeadersAndFirstChunk.FirstBodyChunk)
	}
	moreBodyChunks := m.HeadersAndFirstChunk.MoreBodyChunks
	readCb := func(p []byte) (n int, err error) {
		if buf.Len() > 0 {
			// First flush the our current buffer to p.
			n, err = buf.Read(p)
			if err != nil && err != io.EOF {
				return
			}

			// Did we fill up p, or could p have contained more?
			if n == len(p) {
				return
			}
		}

		if !moreBodyChunks {
			err = io.EOF
			return
		}

		for {
			var r *pb.WafHttpRequest
			r, err = stream.Recv()
			if err != nil {
				// We do not need to care about r if err is io.EOF, because Recv returns (nil, io.EOF) once it has reached the end of the stream.
				// Source: https://grpc.io/docs/reference/go/generated-code/
				// EOF here could happen if a message was "lying" about MoreBodyChunks being true, when actually there were no more messages after it.
				return
			}

			// Subsequent messages from the gRPC stream have to be of type NextBodyChunk.
			m, ok := r.Content.(*pb.WafHttpRequest_NextBodyChunk)
			if !ok {
				err = fmt.Errorf("subsequent gRPC message was not NextBodyChunk")
				return
			}

			moreBodyChunks = m.NextBodyChunk.MoreBodyChunks

			// Copy as much as possible from the gRPC message to p.
			pRemainingSpace := len(p) - n
			bb := m.NextBodyChunk.BodyChunk
			if len(bb) > pRemainingSpace {
				bb = bb[:pRemainingSpace]
			}
			copy(p[n:], bb)
			n += len(bb)

			// If there's anything remaining, put it in the buffer.
			if pRemainingSpace < len(m.NextBodyChunk.BodyChunk) {
				buf.Write(m.NextBodyChunk.BodyChunk[pRemainingSpace:])
			}

			if !moreBodyChunks && buf.Len() == 0 {
				err = io.EOF
				return
			}

			// Did we fill up p?
			if n == len(p) {
				return
			}
		}
	}

	w := &wafHTTPRequestPbWrapper{
		pb:         m.HeadersAndFirstChunk,
		bodyReader: &wafHTTPRequestPbWrapperBodyReader{readCb: readCb},
	}

	allow, err = s.ws.EvalRequest(w)
	if err != nil {
		stream.SendAndClose(&pb.WafDecision{Allow: false})
		s.logger.Warn().Err(err).Msg("Error from s.ws.EvalRequest(w)")
		allow = false
	}

	return stream.SendAndClose(&pb.WafDecision{Allow: allow})
}

func (s *serverImpl) PutConfig(ctx context.Context, in *pb.WAFConfig) (d *pb.PutConfigResponse, err error) {
	config := &configPbWrapper{pb: in}

	err = s.ws.PutConfig(config)
	if err != nil {
		return
	}

	d = &pb.PutConfigResponse{}
	return
}

func (s *serverImpl) DisposeConfig(ctx context.Context, in *pb.WAFConfigVersion) (d *pb.DisposeConfigResponse, err error) {
	err = s.ws.DisposeConfig(int(in.ConfigVersion))
	if err != nil {
		return
	}

	d = &pb.DisposeConfigResponse{}
	return
}

func (s *serverImpl) Serve() error {
	lis, err := net.Listen("tcp", ":37291")
	if err != nil {
		return fmt.Errorf("Failed to listen: %v", err)
	}

	gs := grpc.NewServer()
	pb.RegisterWafServiceServer(gs, s)
	reflection.Register(gs)
	if err := gs.Serve(lis); err != nil {
		return fmt.Errorf("Failed to serve: %v", err)
	}

	return nil
}
