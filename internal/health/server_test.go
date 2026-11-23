package health

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/t0ggl/kube-vpn/internal/wireguard"
)

func TestHealthEndpointsLifecycle(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewServer(":0", "v0.2.0", "wg0", func() ([]wireguard.PeerStats, error) {
		return []wireguard.PeerStats{{Endpoint: "139.28.218.237:1637"}}, nil
	}, logger)
	srv.SetBackend("kernel")

	// Initially not ready and not healthy.
	rec := httptest.NewRecorder()
	srv.httpSrv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("initial /readyz = %d, want 503", rec.Code)
	}

	// Mark healthy.
	srv.Update(true, nil)

	rec = httptest.NewRecorder()
	srv.httpSrv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthy /readyz = %d, want 200", rec.Code)
	}

	rec = httptest.NewRecorder()
	srv.httpSrv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthy /status = %d, want 200", rec.Code)
	}
	var snap StatusSnapshot
	if err := json.NewDecoder(rec.Body).Decode(&snap); err != nil {
		t.Fatalf("decode /status: %v", err)
	}
	if !snap.Ready || !snap.Healthy || snap.Version != "v0.2.0" || snap.Backend != "kernel" || len(snap.Peers) != 1 {
		t.Errorf("unexpected status snapshot: %+v", snap)
	}

	// Mark unhealthy.
	srv.Update(false, errors.New("tunnel timeout"))
	rec = httptest.NewRecorder()
	srv.httpSrv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unhealthy /healthz = %d, want 503", rec.Code)
	}
}
