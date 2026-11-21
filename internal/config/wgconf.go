package config

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// WGConfig represents a parsed standard wg0.conf file.
type WGConfig struct {
	Interface WGInterface
	Peers     []WGPeer
}

// WGInterface represents the [Interface] section of wg0.conf.
type WGInterface struct {
	PrivateKey [32]byte
	Addresses  []netip.Prefix
	DNS        []netip.Addr
	MTU        int
	ListenPort int
}

// WGPeer represents a [Peer] section of wg0.conf.
type WGPeer struct {
	PublicKey           [32]byte
	PresharedKey        *[32]byte
	EndpointHost        string // Hostname or literal IP
	EndpointPort        uint16
	AllowedIPs          []netip.Prefix
	PersistentKeepalive int
}

// EndpointIsIP reports whether the peer's endpoint host is already a literal IP address.
func (p WGPeer) EndpointIsIP() (netip.Addr, bool) {
	addr, err := netip.ParseAddr(p.EndpointHost)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// ParseWGConfigFile reads and parses a WireGuard configuration file from disk.
func ParseWGConfigFile(path string) (*WGConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open wireguard config %s: %w", path, err)
	}
	defer f.Close()
	return ParseWGConfig(f)
}

// ParseWGConfig parses a WireGuard INI-style configuration from r.
func ParseWGConfig(r io.Reader) (*WGConfig, error) {
	cfg := &WGConfig{}
	var section string
	var currentPeer *WGPeer
	hasPrivateKey := false

	scanner := bufio.NewScanner(r)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if idx := strings.IndexAny(line, "#;"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch name {
			case "interface":
				section = "interface"
				currentPeer = nil
			case "peer":
				section = "peer"
				cfg.Peers = append(cfg.Peers, WGPeer{})
				currentPeer = &cfg.Peers[len(cfg.Peers)-1]
			default:
				return nil, fmt.Errorf("line %d: unknown section [%s]", lineNum, name)
			}
			continue
		}

		eq := strings.Index(line, "=")
		if eq < 0 {
			return nil, fmt.Errorf("line %d: expected key = value", lineNum)
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])

		switch section {
		case "interface":
			switch key {
			case "privatekey":
				k, err := parseKey(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: invalid PrivateKey: %w", lineNum, err)
				}
				cfg.Interface.PrivateKey = k
				hasPrivateKey = true
			case "address":
				for _, item := range strings.Split(val, ",") {
					item = strings.TrimSpace(item)
					if item == "" {
						continue
					}
					if strings.Contains(item, "/") {
						p, err := netip.ParsePrefix(item)
						if err != nil {
							return nil, fmt.Errorf("line %d: invalid Address %q: %w", lineNum, item, err)
						}
						cfg.Interface.Addresses = append(cfg.Interface.Addresses, p)
					} else {
						addr, err := netip.ParseAddr(item)
						if err != nil {
							return nil, fmt.Errorf("line %d: invalid Address %q: %w", lineNum, item, err)
						}
						cfg.Interface.Addresses = append(cfg.Interface.Addresses, netip.PrefixFrom(addr, addr.BitLen()))
					}
				}
			case "dns":
				for _, item := range strings.Split(val, ",") {
					item = strings.TrimSpace(item)
					if item == "" {
						continue
					}
					if addr, err := netip.ParseAddr(item); err == nil {
						cfg.Interface.DNS = append(cfg.Interface.DNS, addr.Unmap())
					}
				}
			case "mtu":
				mtu, err := strconv.Atoi(val)
				if err != nil || mtu < 576 || mtu > 65535 {
					return nil, fmt.Errorf("line %d: invalid MTU %q", lineNum, val)
				}
				cfg.Interface.MTU = mtu
			case "listenport":
				p, err := strconv.Atoi(val)
				if err != nil || p < 0 || p > 65535 {
					return nil, fmt.Errorf("line %d: invalid ListenPort %q", lineNum, val)
				}
				cfg.Interface.ListenPort = p
			case "table", "fwmark", "preup", "postup", "predown", "postdown", "saveconfig":
				// Ignored intentionally: kube-vpn manages routing & firewall natively in Kubernetes.
			}
		case "peer":
			if currentPeer == nil {
				return nil, fmt.Errorf("line %d: key outside section", lineNum)
			}
			switch key {
			case "publickey":
				k, err := parseKey(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: invalid PublicKey: %w", lineNum, err)
				}
				currentPeer.PublicKey = k
			case "presharedkey":
				k, err := parseKey(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: invalid PresharedKey: %w", lineNum, err)
				}
				currentPeer.PresharedKey = &k
			case "endpoint":
				host, portStr, err := net.SplitHostPort(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: invalid Endpoint %q: %w", lineNum, val, err)
				}
				p, err := strconv.ParseUint(portStr, 10, 16)
				if err != nil || p == 0 {
					return nil, fmt.Errorf("line %d: invalid Endpoint port %q", lineNum, portStr)
				}
				currentPeer.EndpointHost = strings.TrimSpace(host)
				currentPeer.EndpointPort = uint16(p)
			case "allowedips":
				for _, item := range strings.Split(val, ",") {
					item = strings.TrimSpace(item)
					if item == "" {
						continue
					}
					p, err := netip.ParsePrefix(item)
					if err != nil {
						return nil, fmt.Errorf("line %d: invalid AllowedIPs %q: %w", lineNum, item, err)
					}
					currentPeer.AllowedIPs = append(currentPeer.AllowedIPs, p.Masked())
				}
			case "persistentkeepalive":
				ka, err := strconv.Atoi(val)
				if err != nil || ka < 0 {
					return nil, fmt.Errorf("line %d: invalid PersistentKeepalive %q", lineNum, val)
				}
				currentPeer.PersistentKeepalive = ka
			}
		default:
			return nil, fmt.Errorf("line %d: key %q before any section header", lineNum, key)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read wireguard config: %w", err)
	}

	if !hasPrivateKey {
		return nil, fmt.Errorf("wireguard config missing [Interface] PrivateKey")
	}
	if len(cfg.Interface.Addresses) == 0 {
		return nil, fmt.Errorf("wireguard config missing [Interface] Address")
	}
	if len(cfg.Peers) == 0 {
		return nil, fmt.Errorf("wireguard config missing at least one [Peer] section")
	}
	var zeroKey [32]byte
	for i, peer := range cfg.Peers {
		if peer.PublicKey == zeroKey {
			return nil, fmt.Errorf("peer %d missing PublicKey", i)
		}
		if peer.EndpointHost == "" || peer.EndpointPort == 0 {
			return nil, fmt.Errorf("peer %d missing Endpoint", i)
		}
		if len(peer.AllowedIPs) == 0 {
			return nil, fmt.Errorf("peer %d missing AllowedIPs", i)
		}
	}
	if cfg.Interface.MTU == 0 {
		cfg.Interface.MTU = 1420
	}

	return cfg, nil
}

func parseKey(s string) ([32]byte, error) {
	var out [32]byte
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("expected 32-byte key, got %d bytes", len(b))
	}
	copy(out[:], b)
	return out, nil
}
