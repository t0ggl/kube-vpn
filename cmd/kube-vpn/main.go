package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/t0ggl/kube-vpn/internal/config"
	"github.com/t0ggl/kube-vpn/internal/dns"
	"github.com/t0ggl/kube-vpn/internal/firewall"
	"github.com/t0ggl/kube-vpn/internal/health"
	"github.com/t0ggl/kube-vpn/internal/routing"
	"github.com/t0ggl/kube-vpn/internal/wireguard"
)

var version = "dev"

func main() {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "kube-vpn configuration error: %v\n", err)
		os.Exit(1)
	}

	logger := newLogger(cfg.LogLevel)
	if b, err := os.ReadFile("/version"); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			version = v
		}
	}
	logger.Info("starting kube-vpn",
		"version", version,
		"interface", cfg.WGInterface,
		"backend", cfg.WGBackend,
		"killswitch", cfg.KillswitchEnabled,
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg, logger); err != nil {
		logger.Error("kube-vpn exited with error", "error", err)
		os.Exit(1)
	}
	logger.Info("kube-vpn stopped cleanly")
}

func run(ctx context.Context, cfg *config.Config, logger *slog.Logger) error {
	// 1. Parse wg0.conf (read-only directly from Kubernetes Secret mount).
	wgCfg, err := config.ParseWGConfigFile(cfg.WGConfigPath)
	if err != nil {
		return err
	}

	// 2. Initialize DNS resolver using BOOTSTRAP_DNS or /etc/resolv.conf (CoreDNS).
	resolver, err := dns.NewResolver(cfg.BootstrapDNS)
	if err != nil {
		return err
	}
	logger.Info("initialized DNS resolver", "servers", resolver.Servers)

	// 3. Detect pod's primary CNI interface and default gateway.
	podNet, err := routing.DetectPodNetwork(cfg.WGInterface)
	if err != nil {
		return fmt.Errorf("detect pod network: %w", err)
	}
	podIface := podNet.PrimaryInterface()
	logger.Info("detected pod network",
		"interface", podIface,
		"has_v4", podNet.V4 != nil,
		"has_v6", podNet.V6 != nil,
	)

	// 4. Idempotently clean any leftover WireGuard interface & policy rules from
	//    a previous container restart in this shared Kubernetes Pod netns.
	if err := routing.CleanupStale(cfg.WGInterface, cfg.FWMARK); err != nil {
		return fmt.Errorf("cleanup stale pod network state: %w", err)
	}

	// Build pod input ports list, automatically including the health server port
	// so kubelet HTTP probes work out of the box.
	podInputPorts := append([]config.PortSpec(nil), cfg.PodInputPorts...)
	if hp := cfg.HealthPort(); hp > 0 {
		podInputPorts = append(podInputPorts, config.PortSpec{Port: hp, Proto: "tcp"})
	}

	// 5. Install killswitch BEFORE bringing up the tunnel so zero packets can leak
	//    during startup, endpoint resolution, or tunnel setup.
	var fwMgr *firewall.Manager
	if cfg.KillswitchEnabled {
		fwMgr, err = firewall.NewManager()
		if err != nil {
			return fmt.Errorf("init nftables killswitch: %w", err)
		}
		initialPolicy := firewall.Policy{
			WGInterface:   cfg.WGInterface,
			PodInterface:  podIface,
			FWMARK:        cfg.FWMARK,
			BypassSubnets: cfg.BypassSubnets,
			DNSServers:    resolver.Servers,
			PodInputPorts: podInputPorts,
			VPNInputPorts: cfg.VPNInputPorts,
		}
		if err := fwMgr.Apply(initialPolicy); err != nil {
			return fmt.Errorf("apply bootstrap killswitch: %w", err)
		}
		logger.Info("applied bootstrap nftables killswitch")
	}

	// 6. Resolve WireGuard peer endpoint hostnames (if any).
	preferV4 := podNet.V4 != nil
	resolvedPeers, endpoints, err := resolveAllPeers(ctx, resolver, wgCfg.Peers, preferV4, logger)
	if err != nil {
		return fmt.Errorf("resolve wireguard peer endpoints: %w", err)
	}

	// 7. Atomically update nftables killswitch to permit the resolved WireGuard endpoint(s).
	applyFirewall := func(eps []firewall.Endpoint) error {
		if fwMgr == nil {
			return nil
		}
		return fwMgr.Apply(firewall.Policy{
			WGInterface:   cfg.WGInterface,
			PodInterface:  podIface,
			FWMARK:        cfg.FWMARK,
			Endpoints:     eps,
			BypassSubnets: cfg.BypassSubnets,
			DNSServers:    resolver.Servers,
			PodInputPorts: podInputPorts,
			VPNInputPorts: cfg.VPNInputPorts,
		})
	}
	if err := applyFirewall(endpoints); err != nil {
		return fmt.Errorf("apply killswitch with resolved endpoints: %w", err)
	}

	// 8. Open WireGuard tunnel (kernel with automatic userspace fallback).
	tunnel, err := wireguard.Open(cfg.WGInterface, cfg.WGBackend, cfg.FWMARK, wgCfg, resolvedPeers, logger)
	if err != nil {
		return err
	}
	defer func() {
		logger.Info("shutting down wireguard tunnel")
		if err := tunnel.Close(); err != nil {
			logger.Warn("error closing wireguard tunnel", "error", err)
		}
		if err := routing.CleanupStale(cfg.WGInterface, cfg.FWMARK); err != nil {
			logger.Warn("error cleaning up routing rules", "error", err)
		}
		if fwMgr != nil && !cfg.KillswitchKeepOnExit {
			if err := fwMgr.Delete(); err != nil {
				logger.Warn("error removing nftables killswitch", "error", err)
			}
		} else if fwMgr != nil {
			logger.Info("keeping nftables killswitch active on exit to prevent pod shutdown leaks")
		}
	}()
	logger.Info("wireguard tunnel opened", "backend", tunnel.Backend(), "interface", cfg.WGInterface)

	// 9. Assign interface IPs/MTU and bring interface up.
	if err := routing.ConfigureInterface(cfg.WGInterface, wgCfg.Interface.Addresses, wgCfg.Interface.MTU); err != nil {
		return fmt.Errorf("configure wireguard interface: %w", err)
	}

	// 10. Install policy routing and explicit bypass routes (including cluster DNS servers).
	bypassWithDNS := append([]netip.Prefix(nil), cfg.BypassSubnets...)
	for _, dnsIP := range resolver.Servers {
		bypassWithDNS = append(bypassWithDNS, netip.PrefixFrom(dnsIP, dnsIP.BitLen()))
	}
	hasV4, hasV6 := tunnelFamilies(wgCfg)
	if err := routing.SetupPolicyRouting(cfg.WGInterface, cfg.FWMARK, podNet, hasV4, hasV6, bypassWithDNS); err != nil {
		return fmt.Errorf("setup policy routing: %w", err)
	}
	logger.Info("configured policy routing",
		"table", cfg.FWMARK,
		"ipv4", hasV4,
		"ipv6", hasV6,
		"bypass_routes", len(bypassWithDNS),
	)

	// 11. Start HTTP health/status server for Kubernetes startupProbe/readinessProbe/livenessProbe.
	healthSrv := health.NewServer(cfg.HealthAddr, version, cfg.WGInterface, tunnel.Stats, logger)
	healthSrv.SetBackend(tunnel.Backend())
	if cfg.HealthAddr != "" {
		if err := healthSrv.Start(); err != nil {
			return err
		}
		defer func() {
			shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = healthSrv.Shutdown(shutCtx)
		}()
		logger.Info("health server listening", "addr", cfg.HealthAddr)
	}

	// 12. Run initial connectivity check immediately so /readyz flips 200 ASAP.
	checkHealth := func() bool {
		if err := health.ProbeTarget(ctx, cfg.HealthCheckTarget, cfg.HealthCheckTimeout); err != nil {
			healthSrv.Update(false, err)
			logger.Warn("tunnel connectivity probe failed", "target", cfg.HealthCheckTarget, "error", err)
			return false
		}
		healthSrv.Update(true, nil)
		return true
	}

	reconcileEndpoints := func(reason string) {
		newResolved, newEndpoints, err := resolveAllPeers(ctx, resolver, wgCfg.Peers, preferV4, logger)
		if err != nil {
			logger.Warn("endpoint re-resolution failed", "reason", reason, "error", err)
			return
		}
		changed := false
		for i := range newResolved {
			if newResolved[i].ResolvedIP != resolvedPeers[i].ResolvedIP {
				changed = true
				logger.Info("wireguard peer endpoint IP changed, updating live",
					"reason", reason,
					"host", newResolved[i].Peer.EndpointHost,
					"old_ip", resolvedPeers[i].ResolvedIP,
					"new_ip", newResolved[i].ResolvedIP,
				)
			}
		}
		if !changed {
			return
		}
		// Atomically update firewall BEFORE switching peer endpoint so packets to new IP are allowed.
		if err := applyFirewall(newEndpoints); err != nil {
			logger.Error("failed to update nftables for rotated endpoint", "error", err)
			return
		}
		for i := range newResolved {
			if newResolved[i].ResolvedIP != resolvedPeers[i].ResolvedIP {
				if err := tunnel.UpdatePeerEndpoint(
					newResolved[i].Peer.PublicKey,
					newResolved[i].ResolvedIP,
					newResolved[i].Peer.EndpointPort,
				); err != nil {
					logger.Error("failed to update wireguard peer endpoint", "error", err)
					continue
				}
				resolvedPeers[i].ResolvedIP = newResolved[i].ResolvedIP
			}
		}
	}

	// Give the tunnel a brief initial handshake attempt.
	for attempt := 1; attempt <= 5; attempt++ {
		if checkHealth() {
			logger.Info("tunnel verified healthy and ready")
			break
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}

	// 13. Main watchdog loop: health probes + automatic dynamic DNS endpoint rotation.
	healthTicker := time.NewTicker(cfg.HealthCheckInterval)
	defer healthTicker.Stop()

	var refreshCh <-chan time.Time
	if cfg.EndpointRefreshInterval > 0 {
		refreshTicker := time.NewTicker(cfg.EndpointRefreshInterval)
		defer refreshTicker.Stop()
		refreshCh = refreshTicker.C
	}

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-refreshCh:
			reconcileEndpoints("periodic-refresh")

		case <-healthTicker.C:
			ok := checkHealth()
			if !ok {
				// Immediately re-resolve endpoints in case the VPN provider rotated IPs!
				reconcileEndpoints("health-check-failure")
				// Re-probe once after endpoint reconciliation.
				_ = checkHealth()
				continue
			}

			// Also check if WireGuard handshake has gone stale.
			if cfg.HandshakeStaleAfter > 0 {
				if stats, err := tunnel.Stats(); err == nil {
					for _, st := range stats {
						if !st.LastHandshake.IsZero() && time.Since(st.LastHandshake) > cfg.HandshakeStaleAfter {
							logger.Warn("wireguard handshake is stale, checking for endpoint IP rotation",
								"endpoint", st.Endpoint,
								"age", time.Since(st.LastHandshake).Round(time.Second),
							)
							reconcileEndpoints("stale-handshake")
							break
						}
					}
				}
			}
		}
	}
}

func resolveAllPeers(ctx context.Context, r *dns.Resolver, peers []config.WGPeer, preferV4 bool, logger *slog.Logger) ([]wireguard.ResolvedPeer, []firewall.Endpoint, error) {
	resolved := make([]wireguard.ResolvedPeer, 0, len(peers))
	endpoints := make([]firewall.Endpoint, 0, len(peers))
	for _, p := range peers {
		ip, err := r.ResolveEndpoint(ctx, p.EndpointHost, preferV4)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve peer %s: %w", p.EndpointHost, err)
		}
		if _, isLiteral := p.EndpointIsIP(); !isLiteral {
			logger.Info("resolved wireguard endpoint hostname", "host", p.EndpointHost, "ip", ip, "port", p.EndpointPort)
		}
		resolved = append(resolved, wireguard.ResolvedPeer{
			Peer:       p,
			ResolvedIP: ip,
		})
		endpoints = append(endpoints, firewall.Endpoint{
			IP:   ip,
			Port: p.EndpointPort,
		})
	}
	return resolved, endpoints, nil
}

func tunnelFamilies(wgCfg *config.WGConfig) (hasV4, hasV6 bool) {
	ifaceV4, ifaceV6 := false, false
	for _, a := range wgCfg.Interface.Addresses {
		if a.Addr().Is4() {
			ifaceV4 = true
		} else {
			ifaceV6 = true
		}
	}
	peerV4, peerV6 := false, false
	for _, p := range wgCfg.Peers {
		for _, a := range p.AllowedIPs {
			if a.Addr().Is4() {
				peerV4 = true
			} else {
				peerV6 = true
			}
		}
	}
	return ifaceV4 && peerV4, ifaceV6 && peerV6
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}
