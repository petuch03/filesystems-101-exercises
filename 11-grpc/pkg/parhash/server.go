package parhash

import (
	"context"

	"github.com/pkg/errors"
	"golang.org/x/sync/semaphore"
)

type Config struct {
	ListenAddr   string
	BackendAddrs []string
	Concurrency  int
}

// Implement a server that responds to ParallelHash()
// as declared in /proto/parhash.proto.
//
// The implementation of ParallelHash() must not hash the content
// of buffers on its own. Instead, it must send buffers to backends
// to compute hashes. Buffers must be fanned out to backends in the
// round-robin fashion.
//
// For example, suppose that 2 backends are configured and ParallelHash()
// is called to compute hashes of 5 buffers. In this case it may assign
// buffers to backends in this way:
//
//	backend 0: buffers 0, 2, and 4,
//	backend 1: buffers 1 and 3.
//
// Requests to hash individual buffers must be issued concurrently.
// Goroutines that issue them must run within /pkg/workgroup/Wg. The
// concurrency within workgroups must be limited by Server.sem.
//
// WARNING: requests to ParallelHash() may be concurrent, too.
// Make sure that the round-robin fanout works in that case too,
// and evenly distributes the load across backends.
type Server struct {
	conf       Config
	sem        *semaphore.Weighted
	grpcServer *grpc.Server
	mu         sync.Mutex
	nextBackend int
	backends   []BackendClient
}

func New(conf Config) *Server {
	return &Server{
		conf:       conf,
		sem:        semaphore.NewWeighted(int64(conf.Concurrency)),
		grpcServer: grpc.NewServer(),
		backends:   make([]BackendClient, len(conf.BackendAddrs)),
	}
}

func (s *Server) Start(ctx context.Context) (err error) {
	defer func() { err = errors.Wrap(err, "Start()") }()

	for i, addr := range s.conf.BackendAddrs {
		conn, err := grpc.Dial(addr, grpc.WithInsecure())
		if err != nil {
			return fmt.Errorf("failed to connect to backend %s: %w", addr, err)
		}
		s.backends[i] = NewBackendClient(conn)
	}

	RegisterParallelHashServiceServer(s.grpcServer, s)

	listener, err := net.Listen("tcp", s.conf.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.conf.ListenAddr, err)
	}
	go func() {
		if err := s.grpcServer.Serve(listener); err != nil {
			fmt.Printf("gRPC server stopped: %v\n", err)
		}
	}()

	return nil
}

func (s *Server) ListenAddr() string {
	return s.conf.ListenAddr
}

func (s *Server) ListenAddr() string {
	return s.conf.ListenAddr
}

func (s *Server) ParallelHash(ctx context.Context, req *ParallelHashRequest) (*ParallelHashResponse, error) {
	var wg sync.WaitGroup
	results := make([]*HashResult, len(req.Buffers))
	errChan := make(chan error, len(req.Buffers))

	for i, buffer := range req.Buffers {
		if err := s.sem.Acquire(ctx, 1); err != nil {
			return nil, fmt.Errorf("failed to acquire semaphore: %w", err)
		}

		wg.Add(1)
		go func(idx int, buf []byte) {
			defer wg.Done()
			defer s.sem.Release(1)

			backend := s.getNextBackend()
			resp, err := backend.ComputeHash(ctx, &HashRequest{Buffer: buf})
			if err != nil {
				errChan <- fmt.Errorf("failed to compute hash for buffer %d: %w", idx, err)
				return
			}

			results[idx] = &HashResult{Hash: resp.Hash}
		}(i, buffer)
	}

	wg.Wait()
	close(errChan)

	if len(errChan) > 0 {
		return nil, <-errChan
	}

	return &ParallelHashResponse{Results: results}, nil
}

func (s *Server) getNextBackend() BackendClient {
	s.mu.Lock()
	defer s.mu.Unlock()

	client := s.backends[s.nextBackend]
	s.nextBackend = (s.nextBackend + 1) % len(s.backends)
	return client
}