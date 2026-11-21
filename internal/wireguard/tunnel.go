package wireguard

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/t0ggl/kube-vpn/internal/config"
)

// PeerStats holds runtime telemetry for a single WireGuard peer.
type PeerStats struct {
	PublicKey     string    `json:"public_key"`
	Endpoint      string    `json:"endpoint"`
	LastHandshake time.Time `json:"last_handshake"`
	ReceiveBytes  int64     `json:"receive_bytes"`
	TransmitBytes int64     `json:"transmit_bytes"`
}

// ResolvedPeer pairs a parsed WGPeer with its currently resolved endpoint IP.
type ResolvedPeer struct {
	Peer       config.WGPeer
	ResolvedIP netip.Addr
}

// Tunnel manages a WireGuard interface using either the Linux kernel module
// or an embedded userspace wireguard-go fallback.
type Tunnel struct {
	ifaceName string
	backend   string // "kernel" or "userspace"
	fwmark    uint32
	wgClient  *wgctrl.Client
	userspace *userspaceDevice
	logger    *slog.Logger
}

// Backend returns "kernel" or "userspace".
func (t *Tunnel) Backend() string {
	return t.backend
}

// Open creates and configures the WireGuard tunnel.
func Open(ifaceName, preferredBackend string, fwmark uint32, wgCfg *config.WGConfig, peers []ResolvedPeer, logger *slog.Logger) (*Tunnel, error) {
	t := &Tunnel{
		ifaceName: ifaceName,
		fwmark:    fwmark,
		logger:    logger,
	}

	switch preferredBackend {
	case "kernel":
		if err := t.openKernel(wgCfg, peers); err != nil {
			return nil, fmt.Errorf("open kernel wireguard: %w", err)
		}
		return t, nil
	case "userspace":
		if err := t.openUserspace(wgCfg, peers); err != nil {
			return nil, fmt.Errorf("open userspace wireguard: %w", err)
		}
		return t, nil
	case "auto":
		if err := t.openKernel(wgCfg, peers); err == nil {
			return t, nil
		} else {
			logger.Warn("kernel wireguard unavailable, falling back to embedded wireguard-go userspace backend", "error", err)
		}
		if err := t.openUserspace(wgCfg, peers); err != nil {
			return nil, fmt.Errorf("kernel wireguard unavailable and userspace fallback failed: %w", err)
		}
		return t, nil
	default:
		return nil, fmt.Errorf("unknown backend %q", preferredBackend)
	}
}

func (t *Tunnel) openKernel(wgCfg *config.WGConfig, peers []ResolvedPeer) error {
	link := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{Name: t.ifaceName},
		LinkType:  "wireguard",
	}
	if err := netlink.LinkAdd(link); err != nil {
		if !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("create kernel wireguard link %s: %w", t.ifaceName, err)
		}
	}

	client, err := wgctrl.New()
	if err != nil {
		_ = netlink.LinkDel(link)
		return fmt.Errorf("create wgctrl client: %w", err)
	}

	privKey := wgtypes.Key(wgCfg.Interface.PrivateKey)
	fwmarkInt := int(t.fwmark)
	devCfg := wgtypes.Config{
		PrivateKey:   &privKey,
		FirewallMark: &fwmarkInt,
		ReplacePeers: true,
	}
	if wgCfg.Interface.ListenPort > 0 {
		p := wgCfg.Interface.ListenPort
		devCfg.ListenPort = &p
	}

	for _, rp := range peers {
		devCfg.Peers = append(devCfg.Peers, toWGPeerConfig(rp))
	}

	if err := client.ConfigureDevice(t.ifaceName, devCfg); err != nil {
		_ = client.Close()
		_ = netlink.LinkDel(link)
		return fmt.Errorf("configure kernel wireguard device %s: %w", t.ifaceName, err)
	}

	t.wgClient = client
	t.backend = "kernel"
	return nil
}

func (t *Tunnel) openUserspace(wgCfg *config.WGConfig, peers []ResolvedPeer) error {
	u, err := startUserspaceDevice(t.ifaceName, wgCfg.Interface.MTU, t.logger)
	if err != nil {
		return err
	}
	if err := u.configure(wgCfg, t.fwmark, peers); err != nil {
		u.close()
		return err
	}
	t.userspace = u
	t.backend = "userspace"
	return nil
}

// UpdatePeerEndpoint updates a peer's resolved IP:port in-place without
// restarting the container or recreating the WireGuard interface.
func (t *Tunnel) UpdatePeerEndpoint(pubKey [32]byte, newIP netip.Addr, port uint16) error {
	if t.backend == "kernel" {
		udpAddr := &net.UDPAddr{
			IP:   net.IP(newIP.Unmap().AsSlice()),
			Port: int(port),
		}
		err := t.wgClient.ConfigureDevice(t.ifaceName, wgtypes.Config{
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey:  wgtypes.Key(pubKey),
					UpdateOnly: true,
					Endpoint:   udpAddr,
				},
			},
		})
		if err != nil {
			return fmt.Errorf("update kernel peer endpoint: %w", err)
		}
		return nil
	}

	if t.userspace != nil {
		var sb strings.Builder
		fmt.Fprintf(&sb, "public_key=%s\n", hex.EncodeToString(pubKey[:]))
		fmt.Fprintf(&sb, "endpoint=%s\n", net.JoinHostPort(newIP.Unmap().String(), fmt.Sprintf("%d", port)))
		return t.userspace.dev.IpcSet(sb.String())
	}

	return fmt.Errorf("tunnel not initialized")
}

// Stats returns current handshake timestamps and byte counters for all peers.
func (t *Tunnel) Stats() ([]PeerStats, error) {
	if t.backend == "kernel" && t.wgClient != nil {
		dev, err := t.wgClient.Device(t.ifaceName)
		if err != nil {
			return nil, err
		}
		out := make([]PeerStats, 0, len(dev.Peers))
		for _, p := range dev.Peers {
			ep := ""
			if p.Endpoint != nil {
				ep = p.Endpoint.String()
			}
			out = append(out, PeerStats{
				PublicKey:     p.PublicKey.String(),
				Endpoint:      ep,
				LastHandshake: p.LastHandshakeTime,
				ReceiveBytes:  p.ReceiveBytes,
				TransmitBytes: p.TransmitBytes,
			})
		}
		return out, nil
	}

	if t.userspace != nil {
		return t.userspace.stats()
	}
	return nil, fmt.Errorf("tunnel not initialized")
}

// Close tears down the WireGuard interface and closes handles.
func (t *Tunnel) Close() error {
	var errs []error
	if t.wgClient != nil {
		if err := t.wgClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if t.userspace != nil {
		t.userspace.close()
	}
	if link, err := netlink.LinkByName(t.ifaceName); err == nil {
		if err := netlink.LinkDel(link); err != nil && !errors.Is(err, syscall.ENODEV) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func toWGPeerConfig(rp ResolvedPeer) wgtypes.PeerConfig {
	pc := wgtypes.PeerConfig{
		PublicKey:         wgtypes.Key(rp.Peer.PublicKey),
		ReplaceAllowedIPs: true,
		Endpoint: &net.UDPAddr{
			IP:   net.IP(rp.ResolvedIP.Unmap().AsSlice()),
			Port: int(rp.Peer.EndpointPort),
		},
	}
	if rp.Peer.PresharedKey != nil {
		psk := wgtypes.Key(*rp.Peer.PresharedKey)
		pc.PresharedKey = &psk
	}
	if rp.Peer.PersistentKeepalive > 0 {
		d := time.Duration(rp.Peer.PersistentKeepalive) * time.Second
		pc.PersistentKeepaliveInterval = &d
	}
	for _, p := range rp.Peer.AllowedIPs {
		p = p.Masked()
		pc.AllowedIPs = append(pc.AllowedIPs, net.IPNet{
			IP:   net.IP(p.Addr().AsSlice()),
			Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
		})
	}
	return pc
}
