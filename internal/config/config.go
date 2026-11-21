package config

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// PortSpec describes an inbound port and transport protocol(s).
type PortSpec struct {
	Port  uint16
	Proto string // "tcp", "udp", or "both"
}

// Config holds runtime configuration loaded from environment variables.
type Config struct {
	WGConfigPath            string
	WGInterface             string
	WGBackend               string // "auto", "kernel", "userspace"
	FWMARK                  uint32
	BypassSubnets           []netip.Prefix
	PodInputPorts           []PortSpec
	VPNInputPorts           []PortSpec
	BootstrapDNS            []netip.Addr
	HealthAddr              string
	HealthCheckTarget       string
	HealthCheckInterval     time.Duration
	HealthCheckTimeout      time.Duration
	EndpointRefreshInterval time.Duration
	HandshakeStaleAfter     time.Duration
	KillswitchEnabled       bool
	KillswitchKeepOnExit    bool
	LogLevel                string
}

// LoadFromEnv loads and validates configuration from environment variables.
func LoadFromEnv() (*Config, error) {
	return loadFromLookup(os.LookupEnv)
}

func loadFromLookup(lookup func(string) (string, bool)) (*Config, error) {
	get := func(key, def string) string {
		if v, ok := lookup(key); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
		return def
	}

	cfg := &Config{
		WGConfigPath:      get("WG_CONFIG_PATH", "/etc/wireguard/wg0.conf"),
		WGInterface:       get("WG_INTERFACE", "wg0"),
		WGBackend:         strings.ToLower(get("WG_BACKEND", "auto")),
		HealthAddr:        get("HEALTH_ADDR", ":9999"),
		HealthCheckTarget: get("HEALTH_CHECK_TARGET", "1.1.1.1:443"),
		LogLevel:          strings.ToLower(get("LOG_LEVEL", "info")),
	}

	switch cfg.WGBackend {
	case "auto", "kernel", "userspace":
	default:
		return nil, fmt.Errorf("invalid WG_BACKEND %q: must be auto, kernel, or userspace", cfg.WGBackend)
	}

	fwmarkStr := get("WG_FWMARK", "51820")
	fwmark, err := strconv.ParseUint(fwmarkStr, 0, 32)
	if err != nil || fwmark == 0 {
		return nil, fmt.Errorf("invalid WG_FWMARK %q: must be a positive uint32", fwmarkStr)
	}
	cfg.FWMARK = uint32(fwmark)

	if raw := get("BYPASS_SUBNETS", ""); raw != "" {
		subnets, err := parsePrefixes(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid BYPASS_SUBNETS: %w", err)
		}
		cfg.BypassSubnets = subnets
	}

	if raw := get("POD_INPUT_PORTS", ""); raw != "" {
		ports, err := parsePortSpecs(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid POD_INPUT_PORTS: %w", err)
		}
		cfg.PodInputPorts = ports
	}

	if raw := get("VPN_INPUT_PORTS", ""); raw != "" {
		ports, err := parsePortSpecs(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid VPN_INPUT_PORTS: %w", err)
		}
		cfg.VPNInputPorts = ports
	}

	if raw := get("BOOTSTRAP_DNS", ""); raw != "" {
		addrs, err := parseAddrs(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid BOOTSTRAP_DNS: %w", err)
		}
		cfg.BootstrapDNS = addrs
	}

	cfg.HealthCheckInterval, err = parseDuration(get("HEALTH_CHECK_INTERVAL", "30s"), "HEALTH_CHECK_INTERVAL")
	if err != nil {
		return nil, err
	}
	cfg.HealthCheckTimeout, err = parseDuration(get("HEALTH_CHECK_TIMEOUT", "5s"), "HEALTH_CHECK_TIMEOUT")
	if err != nil {
		return nil, err
	}
	cfg.EndpointRefreshInterval, err = parseDuration(get("ENDPOINT_REFRESH_INTERVAL", "0s"), "ENDPOINT_REFRESH_INTERVAL")
	if err != nil {
		return nil, err
	}
	cfg.HandshakeStaleAfter, err = parseDuration(get("HANDSHAKE_STALE_AFTER", "3m"), "HANDSHAKE_STALE_AFTER")
	if err != nil {
		return nil, err
	}

	cfg.KillswitchEnabled, err = parseBool(get("KILLSWITCH_ENABLED", "true"), "KILLSWITCH_ENABLED")
	if err != nil {
		return nil, err
	}
	cfg.KillswitchKeepOnExit, err = parseBool(get("KILLSWITCH_KEEP_ON_EXIT", "true"), "KILLSWITCH_KEEP_ON_EXIT")
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// HealthPort returns the TCP port extracted from HealthAddr (or 0 if disabled/invalid).
func (c *Config) HealthPort() uint16 {
	if c.HealthAddr == "" {
		return 0
	}
	idx := strings.LastIndex(c.HealthAddr, ":")
	if idx < 0 || idx == len(c.HealthAddr)-1 {
		return 0
	}
	p, err := strconv.ParseUint(c.HealthAddr[idx+1:], 10, 16)
	if err != nil {
		return 0
	}
	return uint16(p)
}

func parsePrefixes(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			p, err := netip.ParsePrefix(item)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", item, err)
			}
			out = append(out, p.Masked())
		} else {
			addr, err := netip.ParseAddr(item)
			if err != nil {
				return nil, fmt.Errorf("invalid IP/CIDR %q: %w", item, err)
			}
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return out, nil
}

func parseAddrs(raw string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		addr, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("invalid IP address %q: %w", item, err)
		}
		out = append(out, addr.Unmap())
	}
	return out, nil
}

func parsePortSpecs(raw string) ([]PortSpec, error) {
	var out []PortSpec
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		proto := "both"
		portPart := item
		if slash := strings.Index(item, "/"); slash >= 0 {
			portPart = strings.TrimSpace(item[:slash])
			proto = strings.ToLower(strings.TrimSpace(item[slash+1:]))
			if proto != "tcp" && proto != "udp" {
				return nil, fmt.Errorf("invalid protocol in %q: must be tcp or udp", item)
			}
		}
		p, err := strconv.ParseUint(portPart, 10, 16)
		if err != nil || p == 0 {
			return nil, fmt.Errorf("invalid port in %q", item)
		}
		out = append(out, PortSpec{Port: uint16(p), Proto: proto})
	}
	return out, nil
}

func parseDuration(raw, name string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("invalid %s %q: must be a non-negative duration", name, raw)
	}
	return d, nil
}

func parseBool(raw, name string) (bool, error) {
	b, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("invalid %s %q: must be true or false", name, raw)
	}
	return b, nil
}
