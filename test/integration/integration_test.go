//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	netPod      = "kubevpn-test-pod"
	netUpstream = "kubevpn-test-upstream"

	podAppIP       = "172.30.10.10"
	vpnServer1IP   = "172.30.10.20"
	vpnServer2IP   = "172.30.10.21"
	bypassSvcIP    = "172.30.10.30"
	directLeakIP   = "172.30.10.40"
	dnsServerIP    = "172.30.10.53"

	vpnServer1UpIP = "172.30.20.20"
	vpnServer2UpIP = "172.30.20.21"
	vpnTargetIP    = "172.30.20.100"

	wgClientIP = "10.200.0.2"
)

type harness struct {
	t       *testing.T
	runtime string // "docker" or "podman"
	repoDir string
	tmpDir  string
	prefix  string
}

func detectRuntime(t *testing.T) string {
	t.Helper()
	if env := os.Getenv("CONTAINER_RUNTIME"); env != "" {
		return env
	}
	if _, err := exec.LookPath("docker"); err == nil {
		if exec.Command("docker", "info").Run() == nil {
			return "docker"
		}
	}
	if _, err := exec.LookPath("podman"); err == nil {
		if exec.Command("podman", "info").Run() == nil {
			return "podman"
		}
	}
	t.Skip("neither docker nor podman is available")
	return ""
}

func (h *harness) run(args ...string) (string, error) {
	cmd := exec.Command(h.runtime, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

func (h *harness) mustRun(args ...string) string {
	h.t.Helper()
	out, err := h.run(args...)
	if err != nil {
		h.t.Fatalf("%s %s failed: %v\n%s", h.runtime, strings.Join(args, " "), err, out)
	}
	return out
}

func (h *harness) name(suffix string) string {
	return h.prefix + "-" + suffix
}

func (h *harness) logs(name string) string {
	out, _ := h.run("logs", name)
	return out
}

func (h *harness) volumeFlag(hostPath, containerPath string) string {
	if h.runtime == "podman" {
		return fmt.Sprintf("%s:%s:ro,z", hostPath, containerPath)
	}
	return fmt.Sprintf("%s:%s:ro", hostPath, containerPath)
}

func waitFor(t *testing.T, timeout time.Duration, desc string, fn func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastMsg string
	for time.Now().Before(deadline) {
		ok, msg := fn()
		if ok {
			return
		}
		lastMsg = msg
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s (last: %s)", desc, lastMsg)
}

func TestEndToEndKubernetesPodBehavior(t *testing.T) {
	rt := detectRuntime(t)
	repoDir, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repo dir: %v", err)
	}

	h := &harness{
		t:       t,
		runtime: rt,
		repoDir: repoDir,
		tmpDir:  t.TempDir(),
		prefix:  fmt.Sprintf("kvpn-%d", time.Now().Unix()%100000),
	}

	// Build images once for the suite.
	t.Logf("building test images using %s...", rt)
	h.mustRun("build", "-t", "kube-vpn:test", "-f", filepath.Join(repoDir, "Dockerfile"), repoDir)
	h.mustRun("build", "-t", "kube-vpn-helper:test", "-f", filepath.Join(repoDir, "test/integration/Dockerfile.helper"), repoDir)
	h.mustRun("build", "-t", "kube-vpn-server:test", "-f", filepath.Join(repoDir, "test/integration/Dockerfile.vpnserver"), repoDir)

	// Clean any stale networks from interrupted runs, then create isolated test networks.
	podNetName := h.name("net-pod")
	upNetName := h.name("net-up")
	t.Cleanup(func() {
		for _, suffix := range []string{"kube-vpn-1", "kube-vpn-2", "pod-app", "vpn-1", "vpn-2", "bypass", "leak", "target", "dns"} {
			_, _ = h.run("rm", "-f", h.name(suffix))
		}
		_, _ = h.run("network", "rm", podNetName)
		_, _ = h.run("network", "rm", upNetName)
	})

	h.mustRun("network", "create", "--subnet", "172.30.10.0/24", podNetName)
	h.mustRun("network", "create", "--subnet", "172.30.20.0/24", upNetName)

	// Generate fresh WireGuard keypairs.
	serverPriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	clientPriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}

	// Write standard wg0.conf using a HOSTNAME endpoint (not a literal IP).
	wgConf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
MTU = 1320

[Peer]
PublicKey = %s
Endpoint = vpn.test.local:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 5
`, clientPriv.String(), wgClientIP, serverPriv.PublicKey().String())

	wgConfPath := filepath.Join(h.tmpDir, "wg0.conf")
	if err := os.WriteFile(wgConfPath, []byte(wgConf), 0o644); err != nil {
		t.Fatalf("write wg0.conf: %v", err)
	}

	// 1. Start DNS server (initially resolves vpn.test.local -> vpnServer1IP).
	h.mustRun("run", "-d", "--name", h.name("dns"),
		"--network", podNetName, "--ip", dnsServerIP,
		"kube-vpn-helper:test", "-mode=dns", "-addr=:53", "-control=:8053", "-ip="+vpnServer1IP)

	// 2. Start upstream VPN target (only reachable via net-up through a VPN server).
	h.mustRun("run", "-d", "--name", h.name("target"),
		"--network", upNetName, "--ip", vpnTargetIP,
		"kube-vpn-helper:test", "-mode=echo", "-addr=:8080")

	// 3. Start bypass service (in BYPASS_SUBNETS) and direct-leak target (NOT in BYPASS_SUBNETS).
	h.mustRun("run", "-d", "--name", h.name("bypass"),
		"--network", podNetName, "--ip", bypassSvcIP,
		"kube-vpn-helper:test", "-mode=echo", "-addr=:8080")

	h.mustRun("run", "-d", "--name", h.name("leak"),
		"--network", podNetName, "--ip", directLeakIP,
		"kube-vpn-helper:test", "-mode=echo", "-addr=:8080")

	// 4. Start two WireGuard VPN servers on both net-pod and net-up.
	startVPNServer := func(suffix, podIP, upIP string) {
		h.mustRun("run", "-d", "--name", h.name(suffix),
			"--network", podNetName, "--ip", podIP,
			"--cap-add=NET_ADMIN",
			"--sysctl", "net.ipv4.ip_forward=1",
			"-e", "WG_SERVER_PRIVATE_KEY="+serverPriv.String(),
			"-e", "WG_CLIENT_PUBLIC_KEY="+clientPriv.PublicKey().String(),
			"kube-vpn-server:test")
		h.mustRun("network", "connect", "--ip", upIP, upNetName, h.name(suffix))
	}
	startVPNServer("vpn-1", vpnServer1IP, vpnServer1UpIP)
	startVPNServer("vpn-2", vpnServer2IP, vpnServer2UpIP)

	// 5. Start paired application container (holds the shared Pod network namespace).
	//    Listens on :8080 (POD_INPUT_PORTS) and :9514 (VPN_INPUT_PORTS).
	h.mustRun("run", "-d", "--name", h.name("pod-app"),
		"--network", podNetName, "--ip", podAppIP,
		"--sysctl", "net.ipv4.conf.all.src_valid_mark=1",
		"--entrypoint", "/bin/sh",
		"kube-vpn-helper:test",
		"-c", "/usr/local/bin/test-helper -mode=echo -addr=:8080 & /usr/local/bin/test-helper -mode=tcp-listen -addr=:9514 & wait")

	// Helper to launch kube-vpn attached to pod-app's shared network namespace.
	startKubeVPN := func(suffix string) {
		h.mustRun("run", "-d", "--name", h.name(suffix),
			"--network", "container:"+h.name("pod-app"),
			"--read-only",
			"--cap-drop=ALL",
			"--cap-add=NET_ADMIN",
			"-v", h.volumeFlag(wgConfPath, "/etc/wireguard/wg0.conf"),
			"-e", "BOOTSTRAP_DNS="+dnsServerIP,
			"-e", "BYPASS_SUBNETS="+bypassSvcIP+"/32",
			"-e", "POD_INPUT_PORTS=8080/tcp",
			"-e", "VPN_INPUT_PORTS=9514/tcp",
			"-e", "HEALTH_CHECK_TARGET="+vpnTargetIP+":8080",
			"-e", "HEALTH_CHECK_INTERVAL=2s",
			"-e", "HEALTH_CHECK_TIMEOUT=2s",
			"-e", "ENDPOINT_REFRESH_INTERVAL=0s",
			"-e", "KILLSWITCH_KEEP_ON_EXIT=true",
			"-e", "LOG_LEVEL=debug",
			"kube-vpn:test")
	}

	probeFrom := func(container, targetURL string) (string, error) {
		return h.run("exec", h.name(container),
			"/usr/local/bin/test-helper", "-mode=probe", "-timeout=2s", "-url="+targetURL)
	}

	// 6. Start kube-vpn sidecar (with --read-only and NO /dev/net/tun!).
	startKubeVPN("kube-vpn-1")

	// --- Scenario 1: Tunnel connectivity, readOnlyRootFilesystem, /readyz & /status ---
	t.Run("VPNTunnelAndReadOnlyRootFS", func(t *testing.T) {
		waitFor(t, 20*time.Second, "/readyz 200 OK", func() (bool, string) {
			out, err := probeFrom("pod-app", "http://127.0.0.1:9999/readyz")
			if err != nil {
				return false, fmt.Sprintf("%v (%s) | logs: %s", err, out, h.logs(h.name("kube-vpn-1")))
			}
			return true, out
		})

		statusRaw, err := probeFrom("pod-app", "http://127.0.0.1:9999/status")
		if err != nil {
			t.Fatalf("GET /status failed: %v (%s)", err, statusRaw)
		}
		var st struct {
			Ready   bool   `json:"ready"`
			Healthy bool   `json:"healthy"`
			Backend string `json:"backend"`
		}
		if err := json.Unmarshal([]byte(statusRaw), &st); err != nil {
			t.Fatalf("unmarshal /status: %v (%s)", err, statusRaw)
		}
		if !st.Ready || !st.Healthy || st.Backend != "kernel" {
			t.Fatalf("unexpected /status: %+v", st)
		}

		// Paired app reaches upstream VPN target and exits with vpn-server-1's IP.
		ipOut, err := probeFrom("pod-app", "http://"+vpnTargetIP+":8080/")
		if err != nil {
			t.Fatalf("paired app could not reach VPN target: %v (%s)", err, ipOut)
		}
		if strings.TrimSpace(ipOut) != vpnServer1UpIP {
			t.Fatalf("VPN target saw client IP %q, want %q (vpn-server-1)", ipOut, vpnServer1UpIP)
		}
	})

	// --- Scenario 2: Bypass subnets, POD_INPUT_PORTS, and VPN_INPUT_PORTS ---
	t.Run("BypassSubnetsAndInputPorts", func(t *testing.T) {
		// Paired app -> bypass service over eth0.
		if out, err := probeFrom("pod-app", "http://"+bypassSvcIP+":8080/"); err != nil {
			t.Fatalf("paired app failed to reach bypass service: %v (%s)", err, out)
		}
		// Bypass service -> paired app WebUI port (POD_INPUT_PORTS=8080/tcp).
		if out, err := probeFrom("bypass", "http://"+podAppIP+":8080/"); err != nil {
			t.Fatalf("bypass service failed to reach pod-app:8080: %v (%s)", err, out)
		}
		// Bypass service -> kube-vpn health port (automatically allowed on eth0).
		if out, err := probeFrom("bypass", "http://"+podAppIP+":9999/healthz"); err != nil {
			t.Fatalf("bypass service failed to reach kube-vpn:9999/healthz: %v (%s)", err, out)
		}
		// VPN server -> paired app forwarded VPN port (VPN_INPUT_PORTS=9514/tcp).
		if out, err := h.run("exec", h.name("vpn-1"), "sh", "-c", "nc -z -w 2 "+wgClientIP+" 9514"); err != nil {
			t.Fatalf("vpn-1 failed to reach VPN_INPUT_PORTS %s:9514: %v (%s)", wgClientIP, err, out)
		}
		// VPN server -> unlisted port (9515) MUST be dropped by killswitch.
		if _, err := h.run("exec", h.name("vpn-1"), "sh", "-c", "nc -z -w 2 "+wgClientIP+" 9515"); err == nil {
			t.Fatalf("expected unlisted VPN port 9515 to be blocked, but connection succeeded")
		}
	})

	// --- Scenario 3: Killswitch blocks non-bypass direct traffic (no leak!) ---
	t.Run("KillswitchBlocksNonBypassTraffic", func(t *testing.T) {
		if out, err := probeFrom("pod-app", "http://"+directLeakIP+":8080/"); err == nil {
			t.Fatalf("LEAK DETECTED: paired app reached non-bypass target %s directly: %s", directLeakIP, out)
		}
	})

	// --- Scenario 4: VPN server goes offline -> connectivity drops, no leak, /healthz 503 ---
	t.Run("KillswitchDropsConnectivityWhenVPNOffline", func(t *testing.T) {
		h.mustRun("stop", "-t", "1", h.name("vpn-1"))

		// App cannot reach VPN target anymore.
		if out, err := probeFrom("pod-app", "http://"+vpnTargetIP+":8080/"); err == nil {
			t.Fatalf("expected VPN target to be unreachable when vpn-1 is stopped, got: %s", out)
		}
		// App STILL cannot leak to non-bypass target.
		if out, err := probeFrom("pod-app", "http://"+directLeakIP+":8080/"); err == nil {
			t.Fatalf("LEAK DETECTED while VPN offline: reached %s: %s", directLeakIP, out)
		}
		// /healthz transitions to 503.
		waitFor(t, 15*time.Second, "/healthz 503 when VPN offline", func() (bool, string) {
			out, err := probeFrom("pod-app", "http://127.0.0.1:9999/healthz")
			return err != nil && strings.Contains(out, "status 503"), out
		})
		// Bypass service remains reachable.
		if out, err := probeFrom("pod-app", "http://"+bypassSvcIP+":8080/"); err != nil {
			t.Fatalf("bypass service should remain reachable while VPN is offline: %v (%s)", err, out)
		}
	})

	// --- Scenario 5: Live dynamic DNS endpoint rotation (zero container restart!) ---
	t.Run("LiveDynamicDNSEndpointRotation", func(t *testing.T) {
		// Point vpn.test.local to vpn-server-2 without restarting kube-vpn.
		h.mustRun("exec", h.name("bypass"), "sh", "-c",
			fmt.Sprintf("wget -qO- --post-data='' 'http://%s:8053/ip?value=%s' || true", dnsServerIP, vpnServer2IP))
		// Verify DNS control updated via busybox/helper.
		out, err := probeFrom("bypass", fmt.Sprintf("http://%s:8053/ip", dnsServerIP))
		if err != nil || strings.TrimSpace(out) != vpnServer2IP {
			t.Fatalf("DNS update failed: out=%q err=%v", out, err)
		}

		// Wait for kube-vpn to auto-detect, re-resolve, atomically update nftables + wg0, and recover.
		waitFor(t, 20*time.Second, "live failover to vpn-server-2", func() (bool, string) {
			ipOut, err := probeFrom("pod-app", "http://"+vpnTargetIP+":8080/")
			if err != nil {
				return false, fmt.Sprintf("%v (%s)", err, ipOut)
			}
			return strings.TrimSpace(ipOut) == vpnServer2UpIP, ipOut
		})

		// Confirm /healthz recovers to 200 OK on the next probe tick.
		waitFor(t, 10*time.Second, "/healthz 200 OK after live endpoint rotation", func() (bool, string) {
			out, err := probeFrom("pod-app", "http://127.0.0.1:9999/healthz")
			return err == nil, out
		})
	})

	// --- Scenario 6: Killswitch persists on exit + idempotent restart in shared Pod netns ---
	t.Run("KillswitchPersistsOnExitAndIdempotentRestart", func(t *testing.T) {
		// Stop kube-vpn (SIGTERM) — KILLSWITCH_KEEP_ON_EXIT=true must keep traffic blocked.
		h.mustRun("stop", "-t", "5", h.name("kube-vpn-1"))
		h.mustRun("rm", "-f", h.name("kube-vpn-1"))

		// App STILL cannot reach VPN target OR leak to non-bypass target!
		if out, err := probeFrom("pod-app", "http://"+vpnTargetIP+":8080/"); err == nil {
			t.Fatalf("expected VPN target unreachable after kube-vpn exit, got: %s", out)
		}
		if out, err := probeFrom("pod-app", "http://"+directLeakIP+":8080/"); err == nil {
			t.Fatalf("LEAK DETECTED after kube-vpn exit: reached %s: %s", directLeakIP, out)
		}

		// Start a brand-new kube-vpn container in the SAME shared pod-app netns
		// (simulating a Kubernetes container restart with leftover netns state).
		startKubeVPN("kube-vpn-2")

		waitFor(t, 20*time.Second, "restarted kube-vpn /readyz 200 OK", func() (bool, string) {
			out, err := probeFrom("pod-app", "http://127.0.0.1:9999/readyz")
			if err != nil {
				return false, fmt.Sprintf("%v (%s) | logs: %s", err, out, h.logs(h.name("kube-vpn-2")))
			}
			return true, out
		})

		ipOut, err := probeFrom("pod-app", "http://"+vpnTargetIP+":8080/")
		if err != nil || strings.TrimSpace(ipOut) != vpnServer2UpIP {
			t.Fatalf("restarted kube-vpn traffic failed: got (%q, %v), want %q", ipOut, err, vpnServer2UpIP)
		}
	})
}
