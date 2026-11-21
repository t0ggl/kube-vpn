package wireguard

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/t0ggl/kube-vpn/internal/config"
)

type userspaceDevice struct {
	dev *device.Device
}

func startUserspaceDevice(ifaceName string, mtu int, logger *slog.Logger) (*userspaceDevice, error) {
	if mtu <= 0 {
		mtu = device.DefaultMTU
	}
	tunDev, err := tun.CreateTUN(ifaceName, mtu)
	if err != nil {
		return nil, fmt.Errorf("create userspace TUN device %s (requires /dev/net/tun): %w", ifaceName, err)
	}

	wgLogger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			logger.Debug(fmt.Sprintf(format, args...), "component", "wireguard-go")
		},
		Errorf: func(format string, args ...any) {
			logger.Error(fmt.Sprintf(format, args...), "component", "wireguard-go")
		},
	}

	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), wgLogger)
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("bring up userspace wireguard device: %w", err)
	}
	return &userspaceDevice{dev: dev}, nil
}

// configure applies WireGuard settings purely in-memory via UAPI (zero filesystem writes).
func (u *userspaceDevice) configure(wgCfg *config.WGConfig, fwmark uint32, peers []ResolvedPeer) error {
	var sb strings.Builder
	fmt.Fprintf(&sb, "private_key=%s\n", hex.EncodeToString(wgCfg.Interface.PrivateKey[:]))
	if wgCfg.Interface.ListenPort > 0 {
		fmt.Fprintf(&sb, "listen_port=%d\n", wgCfg.Interface.ListenPort)
	}
	if fwmark > 0 {
		fmt.Fprintf(&sb, "fwmark=%d\n", fwmark)
	}
	sb.WriteString("replace_peers=true\n")

	for _, rp := range peers {
		fmt.Fprintf(&sb, "public_key=%s\n", hex.EncodeToString(rp.Peer.PublicKey[:]))
		if rp.Peer.PresharedKey != nil {
			fmt.Fprintf(&sb, "preshared_key=%s\n", hex.EncodeToString(rp.Peer.PresharedKey[:]))
		}
		fmt.Fprintf(&sb, "endpoint=%s\n", net.JoinHostPort(rp.ResolvedIP.Unmap().String(), fmt.Sprintf("%d", rp.Peer.EndpointPort)))
		if rp.Peer.PersistentKeepalive > 0 {
			fmt.Fprintf(&sb, "persistent_keepalive_interval=%d\n", rp.Peer.PersistentKeepalive)
		}
		sb.WriteString("replace_allowed_ips=true\n")
		for _, cidr := range rp.Peer.AllowedIPs {
			fmt.Fprintf(&sb, "allowed_ip=%s\n", cidr.Masked().String())
		}
	}

	if err := u.dev.IpcSet(sb.String()); err != nil {
		return fmt.Errorf("configure userspace wireguard UAPI: %w", err)
	}
	return nil
}

func (u *userspaceDevice) stats() ([]PeerStats, error) {
	raw, err := u.dev.IpcGet()
	if err != nil {
		return nil, err
	}
	var out []PeerStats
	var cur *PeerStats
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			pubBytes, _ := hex.DecodeString(v)
			out = append(out, PeerStats{PublicKey: base64.StdEncoding.EncodeToString(pubBytes)})
			cur = &out[len(out)-1]
		case "endpoint":
			if cur != nil {
				cur.Endpoint = v
			}
		case "last_handshake_time_sec":
			if cur != nil {
				if sec, err := strconv.ParseInt(v, 10, 64); err == nil && sec > 0 {
					cur.LastHandshake = time.Unix(sec, 0)
				}
			}
		case "rx_bytes":
			if cur != nil {
				cur.ReceiveBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		case "tx_bytes":
			if cur != nil {
				cur.TransmitBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		}
	}
	return out, nil
}

func (u *userspaceDevice) close() {
	if u.dev != nil {
		u.dev.Close()
	}
}
