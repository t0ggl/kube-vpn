package dns

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

// Resolver resolves WireGuard endpoint hostnames using explicitly configured
// bootstrap DNS servers or Kubernetes pod nameservers from /etc/resolv.conf.
type Resolver struct {
	Servers []netip.Addr
	Timeout time.Duration
}

// NewResolver constructs a Resolver. If explicitServers is empty, it parses
// /etc/resolv.conf to discover the pod's cluster DNS servers (e.g. CoreDNS).
func NewResolver(explicitServers []netip.Addr) (*Resolver, error) {
	servers := append([]netip.Addr(nil), explicitServers...)
	if len(servers) == 0 {
		parsed, err := ParseResolvConfFile("/etc/resolv.conf")
		if err != nil {
			return nil, fmt.Errorf("read /etc/resolv.conf: %w", err)
		}
		servers = parsed
	}
	return &Resolver{
		Servers: servers,
		Timeout: 5 * time.Second,
	}, nil
}

// ParseResolvConfFile reads nameserver IP addresses from a resolv.conf file.
func ParseResolvConfFile(path string) ([]netip.Addr, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseResolvConf(f)
}

// ParseResolvConf extracts unique valid nameserver IPs from resolv.conf content.
func ParseResolvConf(r io.Reader) ([]netip.Addr, error) {
	var out []netip.Addr
	seen := make(map[netip.Addr]struct{})
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if addr, err := netip.ParseAddr(fields[1]); err == nil {
				addr = addr.Unmap()
				if _, exists := seen[addr]; !exists {
					seen[addr] = struct{}{}
					out = append(out, addr)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ResolveEndpoint resolves host (which may already be a literal IP or a DNS name)
// into a concrete IP address. Prefers IPv4 when preferV4 is true.
func (r *Resolver) ResolveEndpoint(ctx context.Context, host string, preferV4 bool) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap(), nil
	}

	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	// Try each configured nameserver explicitly via UDP/TCP so we never depend on
	// glibc NSS or get stuck if one nameserver is unreachable.
	var lastErr error
	servers := r.Servers
	if len(servers) == 0 {
		// Fallback to system default resolver if no nameservers were found.
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("resolve %q: %w", host, err)
		}
		return pickAddr(ips, preferV4)
	}

	for _, ns := range servers {
		nsAddr := net.JoinHostPort(ns.String(), "53")
		netResolver := &net.Resolver{
			PreferGo: true,
			Dial: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(dialCtx, network, nsAddr)
			},
		}
		qCtx, cancel := context.WithTimeout(ctx, timeout)
		ips, err := netResolver.LookupNetIP(qCtx, "ip", host)
		cancel()
		if err == nil && len(ips) > 0 {
			return pickAddr(ips, preferV4)
		}
		lastErr = err
	}

	return netip.Addr{}, fmt.Errorf("resolve %q via %v: %w", host, servers, lastErr)
}

func pickAddr(ips []netip.Addr, preferV4 bool) (netip.Addr, error) {
	if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("no IP addresses returned")
	}
	for _, ip := range ips {
		ip = ip.Unmap()
		if preferV4 && ip.Is4() {
			return ip, nil
		}
		if !preferV4 && ip.Is6() {
			return ip, nil
		}
	}
	return ips[0].Unmap(), nil
}
