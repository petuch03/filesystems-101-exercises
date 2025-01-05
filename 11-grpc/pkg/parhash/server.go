package parhash

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/pkg/errors"
	"google.golang.org/grpc"

	hashpb "fs101ex/pkg/gen/hashsvc"
	parhashpb "fs101ex/pkg/gen/parhashsvc"
	"fs101ex/pkg/workgroup"
	"golang.org/x/sync/semaphore"
)

type Config struct {
	ListenAddr   string
	BackendAddrs []string
	Concurrency  int
}

type Server struct {
	conf Config

	sem *semaphore.Weighted

	// For managing server lifecycle
    stop     context.CancelFunc
    listener net.Listener
    wg       sync.WaitGroup

    // For managing backend connections
    backendClients []hashpb.HashSvcClient
    nextBackend   atomic.Uint64 // For round-robin distribution
}

func New(conf Config) *Server {
	return &Server{
		conf: conf,
		sem:  semaphore.NewWeighted(int64(conf.Concurrency)),
	}
}

func (s *Server) Start(ctx context.Context) (err error) {
	defer func() { err = errors.Wrap(err, "Start()") }()

	// Create a cancelable context for server lifecycle
	ctx, s.stop = context.WithCancel(ctx)

	// Initialize connections to all backend servers
	s.backendClients = make([]hashpb.HashSvcClient, len(s.conf.BackendAddrs))
	for i, addr := range s.conf.BackendAddrs {
		conn, err := grpc.Dial(addr, grpc.WithInsecure())
		if err != nil {
			return errors.Wrapf(err, "failed to connect to backend %s", addr)
		}
		s.backendClients[i] = hashpb.NewHashSvcClient(conn)
	}

	// Start listening for incoming connections
	s.listener, err = net.Listen("tcp", s.conf.ListenAddr)
	if err != nil {
		return errors.Wrap(err, "failed to start listener")
	}

	// Create and start gRPC server
	srv := grpc.NewServer()
	parhashpb.RegisterParallelHashSvcServer(srv, s)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := srv.Serve(s.listener); err != nil {
			// Log error but don't return it as this is running in a goroutine
			// In production, you'd want to use proper logging here
			_ = err
		}
	}()

	// Start goroutine to handle graceful shutdown
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-ctx.Done()
		srv.GracefulStop()
		s.listener.Close()
	}()

	return nil
}

func (s *Server) ListenAddr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func (s *Server) Stop() {
	if s.stop != nil {
		s.stop()
	}
	s.wg.Wait()
}

func (s *Server) getNextBackend() hashpb.HashSvcClient {
	// Get next backend index using atomic counter for thread safety
	nextIndex := s.nextBackend.Add(1) % uint64(len(s.backendClients))
	return s.backendClients[nextIndex]
}

func (s *Server) ParallelHash(ctx context.Context, req *parhashpb.ParHashReq) (*parhashpb.ParHashResp, error) {
	if len(req.Data) == 0 {
		return &parhashpb.ParHashResp{}, nil
	}

	// Create response slice with exact capacity
	hashes := make([][]byte, len(req.Data))

	// Create workgroup for parallel processing
	wg := workgroup.New(workgroup.Config{Sem: s.sem})

	// Process each buffer concurrently
	for i, data := range req.Data {
		i, data := i, data // Create new variables for goroutine closure

		wg.Go(ctx, func(ctx context.Context) error {
			// Get next backend using round-robin
			backend := s.getNextBackend()

			// Send hash request to backend
			resp, err := backend.Hash(ctx, &hashpb.HashReq{Data: data})
			if err != nil {
				return errors.Wrapf(err, "backend hash failed for buffer %d", i)
			}

			// Store result in correct position
			hashes[i] = resp.Hash
			return nil
		})
	}

	// Wait for all hash operations to complete
	if err := wg.Wait(); err != nil {
		return nil, errors.Wrap(err, "parallel hash failed")
	}

	return &parhashpb.ParHashResp{
		Hashes: hashes,
	}, nil
}
