package config

import (
	"testing"
	"time"
)

func TestLoadFromLookupDefaults(t *testing.T) {
	cfg, err := loadFromLookup(func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.WGConfigPath != "/etc/wireguard/wg0.conf" {
		t.Errorf("WGConfigPath = %q", cfg.WGConfigPath)
	}
	if cfg.WGInterface != "wg0" {
		t.Errorf("WGInterface = %q", cfg.WGInterface)
	}
	if cfg.WGBackend != "auto" {
		t.Errorf("WGBackend = %q", cfg.WGBackend)
	}
	if cfg.FWMARK != 51820 {
		t.Errorf("FWMARK = %d", cfg.FWMARK)
	}
	if !cfg.KillswitchEnabled || !cfg.KillswitchKeepOnExit {
		t.Errorf("killswitch defaults should be enabled")
	}
	if cfg.HealthPort() != 9999 {
		t.Errorf("HealthPort() = %d, want 9999", cfg.HealthPort())
	}
}

func TestLoadFromLookupCustom(t *testing.T) {
	env := map[string]string{
		"WG_CONFIG_PATH":            "/secrets/wg0.conf",
		"WG_BACKEND":                "kernel",
		"BYPASS_SUBNETS":            "10.244.0.0/16, 10.96.0.0/12, 192.168.1.1",
		"POD_INPUT_PORTS":           "8080/tcp, 9090",
		"VPN_INPUT_PORTS":           "9514",
		"BOOTSTRAP_DNS":             "10.96.0.10,1.1.1.1",
		"HEALTH_ADDR":               ":8081",
		"HEALTH_CHECK_INTERVAL":     "15s",
		"ENDPOINT_REFRESH_INTERVAL": "2m",
		"KILLSWITCH_KEEP_ON_EXIT":   "false",
	}
	cfg, err := loadFromLookup(func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.BypassSubnets) != 3 {
		t.Fatalf("BypassSubnets len = %d, want 3", len(cfg.BypassSubnets))
	}
	if cfg.BypassSubnets[2].String() != "192.168.1.1/32" {
		t.Errorf("single IP should normalize to /32, got %s", cfg.BypassSubnets[2])
	}
	if len(cfg.PodInputPorts) != 2 || cfg.PodInputPorts[0].Proto != "tcp" || cfg.PodInputPorts[1].Proto != "both" {
		t.Errorf("PodInputPorts = %+v", cfg.PodInputPorts)
	}
	if len(cfg.VPNInputPorts) != 1 || cfg.VPNInputPorts[0].Port != 9514 || cfg.VPNInputPorts[0].Proto != "both" {
		t.Errorf("VPNInputPorts = %+v", cfg.VPNInputPorts)
	}
	if len(cfg.BootstrapDNS) != 2 {
		t.Errorf("BootstrapDNS = %+v", cfg.BootstrapDNS)
	}
	if cfg.HealthPort() != 8081 {
		t.Errorf("HealthPort() = %d, want 8081", cfg.HealthPort())
	}
	if cfg.HealthCheckInterval != 15*time.Second {
		t.Errorf("HealthCheckInterval = %v", cfg.HealthCheckInterval)
	}
	if cfg.KillswitchKeepOnExit {
		t.Errorf("KillswitchKeepOnExit should be false")
	}
}

func TestLoadFromLookupValidationErrors(t *testing.T) {
	cases := []map[string]string{
		{"WG_BACKEND": "invalid"},
		{"WG_FWMARK": "0"},
		{"BYPASS_SUBNETS": "not-a-cidr"},
		{"POD_INPUT_PORTS": "8080/icmp"},
		{"VPN_INPUT_PORTS": "99999"},
		{"BOOTSTRAP_DNS": "not-an-ip"},
		{"HEALTH_CHECK_INTERVAL": "-5s"},
	}
	for i, env := range cases {
		_, err := loadFromLookup(func(k string) (string, bool) {
			v, ok := env[k]
			return v, ok
		})
		if err == nil {
			t.Errorf("case %d (%v): expected error, got nil", i, env)
		}
	}
}
