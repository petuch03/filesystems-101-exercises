package parhash

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"golang.org/x/sync/semaphore"

	hashpb "fs101ex/pkg/gen/hashsvc"
	parhashpb "fs101ex/pkg/gen/parhashsvc"
	"fs101ex/pkg/workgroup"
)

type Config struct {
	ListenAddr   string
	BackendAddrs []string
	Concurrency  int
}

type Server struct {
	conf Config

	sem *semaphore.Weighted

    stop     context.CancelFunc
    listener net.Listener
    wg       sync.WaitGroup

    backendClients []hashpb.HashSvcClient
}

func New(conf Config) *Server {
	return &Server{
		conf: conf,
		sem:  semaphore.NewWeighted(int64(conf.Concurrency)),
	}
}

func (s *Server) Start(ctx context.Context) (err error) {
	defer func() { err = errors.Wrap(err, "Start()") }()

	ctx, s.stop = context.WithCancel(ctx)

	s.backendClients = make([]hashpb.HashSvcClient, len(s.conf.BackendAddrs))
	for i, addr := range s.conf.BackendAddrs {
		conn, err := grpc.Dial(addr, grpc.WithInsecure())
		if err != nil {
			return errors.Wrapf(err, "failed to connect to backend %s", addr)
		}
		s.backendClients[i] = hashpb.NewHashSvcClient(conn)
	}

	s.listener, err = net.Listen("tcp", s.conf.ListenAddr)
	if err != nil {
		return errors.Wrap(err, "failed to start listener")
	}

	srv := grpc.NewServer()
	parhashpb.RegisterParallelHashSvcServer(srv, s)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := srv.Serve(s.listener); err != nil {
			_ = err
		}
	}()

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
	nextIndex := s.nextBackend.Add(1) % uint64(len(s.backendClients))
	return s.backendClients[nextIndex]
}

func (s *Server) ParallelHash(ctx context.Context, req *parhashpb.ParHashReq) (*parhashpb.ParHashResp, error) {
	if len(req.Data) == 0 {
		return &parhashpb.ParHashResp{}, nil
	}

	hashes := make([][]byte, len(req.Data))

	wg := workgroup.New(workgroup.Config{Sem: s.sem})

	for i, data := range req.Data {
		i, data := i, data

		wg.Go(ctx, func(ctx context.Context) error {
			backend := s.getNextBackend()

			resp, err := backend.Hash(ctx, &hashpb.HashReq{Data: data})
			if err != nil {
				return errors.Wrapf(err, "backend hash failed for buffer %d", i)
			}

			hashes[i] = resp.Hash
			return nil
		})
	}

	if err := wg.Wait(); err != nil {
		return nil, errors.Wrap(err, "parallel hash failed")
	}

	return &parhashpb.ParHashResp{
		Hashes: hashes,
	}, nil
}
