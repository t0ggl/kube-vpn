package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func testKey(fill byte) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = fill
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestParseWGConfigHostnameEndpoint(t *testing.T) {
	raw := `
# AirVPN-style WireGuard config with hostname endpoint
[Interface]
PrivateKey = ` + testKey(1) + `
Address = 10.128.0.2/32, fd7d:76ee:e68f:a993::2/128
DNS = 10.128.0.1
MTU = 1320

[Peer]
PublicKey = ` + testKey(2) + `
PresharedKey = ` + testKey(3) + `
Endpoint = earth3.vpn.airdns.org:1637
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 15
`
	cfg, err := ParseWGConfig(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Interface.MTU != 1320 {
		t.Errorf("MTU = %d, want 1320", cfg.Interface.MTU)
	}
	if len(cfg.Interface.Addresses) != 2 {
		t.Fatalf("Addresses len = %d, want 2", len(cfg.Interface.Addresses))
	}
	if len(cfg.Peers) != 1 {
		t.Fatalf("Peers len = %d, want 1", len(cfg.Peers))
	}
	peer := cfg.Peers[0]
	if peer.EndpointHost != "earth3.vpn.airdns.org" || peer.EndpointPort != 1637 {
		t.Errorf("Endpoint = %s:%d", peer.EndpointHost, peer.EndpointPort)
	}
	if _, isIP := peer.EndpointIsIP(); isIP {
		t.Errorf("expected hostname, not IP")
	}
	if peer.PresharedKey == nil {
		t.Errorf("expected PresharedKey to be set")
	}
	if peer.PersistentKeepalive != 15 {
		t.Errorf("PersistentKeepalive = %d, want 15", peer.PersistentKeepalive)
	}
}

func TestParseWGConfigLiteralIPv6Endpoint(t *testing.T) {
	raw := `
[Interface]
PrivateKey = ` + testKey(4) + `
Address = 10.0.0.2/24

[Peer]
PublicKey = ` + testKey(5) + `
Endpoint = [2001:db8::1]:51820
AllowedIPs = 0.0.0.0/0
`
	cfg, err := ParseWGConfig(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Interface.MTU != 1420 {
		t.Errorf("default MTU = %d, want 1420", cfg.Interface.MTU)
	}
	ip, ok := cfg.Peers[0].EndpointIsIP()
	if !ok || ip.String() != "2001:db8::1" {
		t.Errorf("EndpointIsIP = (%v, %v)", ip, ok)
	}
}

func TestParseWGConfigErrors(t *testing.T) {
	_, err := ParseWGConfig(strings.NewReader("[Interface]\nAddress = 10.0.0.2/32\n"))
	if err == nil {
		t.Fatalf("expected error for missing PrivateKey")
	}
}
