package parhash

import (
	"context"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/semaphore"
)

type Config struct {
	ListenAddr   string
	BackendAddrs []string
	Concurrency  int

	Prom prometheus.Registerer
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
//
// The server must report the following performance counters to Prometheus:
//
//  1. nr_requests: a counter that is incremented every time a call
//     is made to ParallelHash(),
//
//  2. subquery_durations: a histogram that tracks durations of calls
//     to backends.
//     It must have a label `backend`.
//     Each subquery_durations{backed=backend_addr} must be a histogram
//     with 24 exponentially growing buckets ranging from 0.1ms to 10s.
//
// Both performance counters must be placed to Prometheus namespace "parhash".
type Server struct {
	conf Config

	sem *semaphore.Weighted

    stop     context.CancelFunc
    listener net.Listener
    wg       sync.WaitGroup

    backendClients []hashpb.HashSvcClient
    nextBackend   atomic.Uint64

    // Prometheus metrics
    requestCounter      prometheus.Counter
    subqueryHistograms map[string]prometheus.Observer
}

func New(conf Config) *Server {
	s := &Server{
		conf: conf,
		sem:  semaphore.NewWeighted(int64(conf.Concurrency)),
	}

	// Initialize Prometheus metrics
	s.requestCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "parhash",
		Name:      "nr_requests",
		Help:      "Number of ParallelHash requests received",
	})

	// Create histogram for each backend
	histogramOpts := prometheus.HistogramOpts{
		Namespace: "parhash",
		Name:      "subquery_durations",
		Help:      "Duration of backend hash requests",
		// 24 buckets from 0.1ms to 10s
		Buckets: prometheus.ExponentialBuckets(0.0001, 1.7, 24),
	}

	s.subqueryHistograms = make(map[string]prometheus.Observer, len(conf.BackendAddrs))
	for _, addr := range conf.BackendAddrs {
		histogram := prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: histogramOpts.Namespace,
			Name:      histogramOpts.Name,
			Help:      histogramOpts.Help,
			Buckets:   histogramOpts.Buckets,
			ConstLabels: prometheus.Labels{
				"backend": addr,
			},
		})
		s.subqueryHistograms[addr] = histogram
		conf.Prom.MustRegister(histogram)
	}

	conf.Prom.MustRegister(s.requestCounter)
	return s
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

func (s *Server) getNextBackend() (hashpb.HashSvcClient, string) {
	nextIndex := s.nextBackend.Add(1) % uint64(len(s.backendClients))
	return s.backendClients[nextIndex], s.conf.BackendAddrs[nextIndex]
}

func (s *Server) ParallelHash(ctx context.Context, req *parhashpb.ParHashReq) (*parhashpb.ParHashResp, error) {
	s.requestCounter.Inc()

    if len(req.Data) == 0 {
		return &parhashpb.ParHashResp{}, nil
	}

	hashes := make([][]byte, len(req.Data))

	wg := workgroup.New(workgroup.Config{Sem: s.sem})

	for i, data := range req.Data {
		i, data := i, data

		wg.Go(ctx, func(ctx context.Context) error {
			backend, backendAddr := s.getNextBackend()

			start := time.Now()
			defer func() {
				duration := time.Since(start).Seconds()
				if histogram := s.subqueryHistograms[backendAddr]; histogram != nil {
					histogram.Observe(duration)
				}
			}()

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