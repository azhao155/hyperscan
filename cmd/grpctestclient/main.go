package main

import (
	pb "azwaf/proto"
	"bufio"
	"context"
	"flag"
	"fmt"
	"google.golang.org/grpc"
	"io"
	"log"
	"net/http"
	"os"
)

// A command line utility to send test requests to Azwaf
func main() {
	// Parse command line args
	grpcHostArg := flag.String("grpchost", "localhost:37291", "Azwaf gRPC host to send the request to.")
	uriArg := flag.String("uri", "/index.php?hello=world", "URI to pack into the request. Cannot be used with -rawrequest.")
	rawRequestFilenameArg := flag.String("rawrequest", "./myrequest.txt", "Path to file containing a full HTTP request. Cannot be used with -uri.")
	flag.Parse()
	wasFlagSet := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { wasFlagSet[f.Name] = true })
	if wasFlagSet["uri"] && wasFlagSet["rawrequest"] {
		log.Fatalf("uri cannot be provided together with rawrequest\n")
	}

	uri := *uriArg
	var headers []*pb.HeaderPair
	var bodyReader io.Reader
	var buf [61440]byte // 60 kibibytes
	var bodyChunk []byte
	moreBodyChunks := false

	// Read raw request from file if rawrequest command line arg was given
	if wasFlagSet["rawrequest"] {
		file, err := os.Open(*rawRequestFilenameArg)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		defer file.Close()

		r := bufio.NewReader(file)
		req, err := http.ReadRequest(r)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}

		uri = req.RequestURI
		for headername, values := range req.Header {
			for _, v := range values {
				headers = append(headers, &pb.HeaderPair{Key: headername, Value: v})
			}
		}

		// Read first body chunk
		moreBodyChunks = true
		bodyReader = req.Body
		n, err := bodyReader.Read(buf[:])
		if err != nil {
			if err == io.EOF {
				moreBodyChunks = false
			} else {
				fmt.Printf("%v\n", err)
				return
			}
		}
		bodyChunk = buf[:n]
	}

	// Establish gRPC connection
	conn, err := grpc.Dial(*grpcHostArg, grpc.WithInsecure())
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	defer conn.Close()
	client := pb.NewWafServiceClient(conn)
	stream, err := client.EvalRequest(context.Background())
	if err != nil {
		log.Fatalf("%v.EvalRequest(_) = _, %v", client, err)
	}

	// Send first message
	log.Printf("sending HeadersAndFirstChunk")
	r := &pb.WafHttpRequest{
		Content: &pb.WafHttpRequest_HeadersAndFirstChunk{
			HeadersAndFirstChunk: &pb.HeadersAndFirstChunk{
				Uri:            uri,
				Headers:        headers,
				FirstBodyChunk: bodyChunk,
				MoreBodyChunks: moreBodyChunks,
			},
		},
	}
	if err := stream.Send(r); err != nil {
		if err == io.EOF {
			log.Printf("got EOF from gRPC server")
		} else {
			log.Fatalf("%v.Send(_) = %v", stream, err)
		}
	}

	// Send more messages if larger request body
	for moreBodyChunks {
		n, err := bodyReader.Read(buf[:])
		if err != nil {
			if err == io.EOF {
				moreBodyChunks = false
			} else {
				log.Fatalf("%v", err)
			}
		}
		bodyChunk = buf[:n]

		log.Printf("sending NextBodyChunk")
		r := &pb.WafHttpRequest{
			Content: &pb.WafHttpRequest_NextBodyChunk{
				NextBodyChunk: &pb.NextBodyChunk{
					BodyChunk:      bodyChunk,
					MoreBodyChunks: moreBodyChunks,
				},
			},
		}
		if err := stream.Send(r); err != nil {
			if err == io.EOF {
				log.Printf("got EOF from gRPC server")
				moreBodyChunks = false
			} else {
				log.Fatalf("%v.Send(_) = %v", stream, err)
			}
		}
	}

	reply, err := stream.CloseAndRecv()
	if err != nil {
		log.Fatalf("%v.CloseAndRecv() got error %v", stream, err)
	}

	if reply == nil {
		log.Fatalf("reply was nil")
	} else {
		log.Printf("reply.Allow: %v", reply.Allow)
	}
}
