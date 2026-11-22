package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/t0ggl/kube-vpn/internal/wireguard"
)

// StatusSnapshot is returned by GET /status.
type StatusSnapshot struct {
	Ready          bool                  `json:"ready"`
	Healthy        bool                  `json:"healthy"`
	Backend        string                `json:"backend"`
	Interface      string                `json:"interface"`
	LastCheck      time.Time             `json:"last_check"`
	LastError      string                `json:"last_error,omitempty"`
	StartedAt      time.Time             `json:"started_at"`
	UptimeSeconds  int64                 `json:"uptime_seconds"`
	Peers          []wireguard.PeerStats `json:"peers,omitempty"`
}

// Server serves /readyz, /healthz, and /status for Kubernetes probes and observability.
type Server struct {
	mu        sync.RWMutex
	ready     bool
	healthy   bool
	lastCheck time.Time
	lastErr   string
	backend   string
	ifaceName string
	startedAt time.Time
	statsFn   func() ([]wireguard.PeerStats, error)
	httpSrv   *http.Server
	logger    *slog.Logger
}

// NewServer creates a new health HTTP server bound to addr.
func NewServer(addr, ifaceName string, statsFn func() ([]wireguard.PeerStats, error), logger *slog.Logger) *Server {
	s := &Server{
		ifaceName: ifaceName,
		startedAt: time.Now().UTC(),
		statsFn:   statsFn,
		logger:    logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", s.handleReadyz)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/status", s.handleStatus)

	s.httpSrv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s
}

// SetBackend records which WireGuard backend ("kernel" or "userspace") is active.
func (s *Server) SetBackend(backend string) {
	s.mu.Lock()
	s.backend = backend
	s.mu.Unlock()
}

// Update records the outcome of a health check.
func (s *Server) Update(healthy bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastCheck = time.Now().UTC()
	s.healthy = healthy
	if healthy {
		s.ready = true
		s.lastErr = ""
	} else if err != nil {
		s.lastErr = err.Error()
	}
}

// Start begins serving HTTP requests in a background goroutine.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.httpSrv.Addr)
	if err != nil {
		return fmt.Errorf("listen health server on %s: %w", s.httpSrv.Addr, err)
	}
	go func() {
		if err := s.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.logger.Error("health server exited unexpectedly", "error", err)
		}
	}()
	return nil
}

// Shutdown gracefully stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	ready := s.ready && s.healthy
	lastErr := s.lastErr
	s.mu.RUnlock()

	if !ready {
		http.Error(w, "not ready: "+lastErr, http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	healthy := s.healthy
	lastErr := s.lastErr
	s.mu.RUnlock()

	if !healthy {
		http.Error(w, "unhealthy: "+lastErr, http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	snap := StatusSnapshot{
		Ready:         s.ready,
		Healthy:       s.healthy,
		Backend:       s.backend,
		Interface:     s.ifaceName,
		LastCheck:     s.lastCheck,
		LastError:     s.lastErr,
		StartedAt:     s.startedAt,
		UptimeSeconds: int64(time.Since(s.startedAt).Seconds()),
	}
	s.mu.RUnlock()

	if s.statsFn != nil {
		if peers, err := s.statsFn(); err == nil {
			snap.Peers = peers
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if !snap.Healthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(snap)
}

// ProbeTarget verifies active connectivity through the VPN tunnel.
// Supported formats:
//   - "none" or "": skip active network probe (rely on handshake freshness only)
//   - "http://..." or "https://...": HTTP GET expecting 2xx-3xx
//   - "host:port" (e.g. "1.1.1.1:443"): TCP connect check
func ProbeTarget(ctx context.Context, target string, timeout time.Duration) error {
	target = strings.TrimSpace(target)
	if target == "" || strings.EqualFold(target, "none") {
		return nil
	}

	pCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		req, err := http.NewRequestWithContext(pCtx, http.MethodGet, target, nil)
		if err != nil {
			return fmt.Errorf("invalid health check URL %q: %w", target, err)
		}
		client := &http.Client{Timeout: timeout}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("http probe %s failed: %w", target, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 400 {
			return fmt.Errorf("http probe %s returned status %d", target, resp.StatusCode)
		}
		return nil
	}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(pCtx, "tcp", target)
	if err != nil {
		return fmt.Errorf("tcp probe %s failed: %w", target, err)
	}
	_ = conn.Close()
	return nil
}
