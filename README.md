# kube-vpn

A minimal, Kubernetes-native WireGuard VPN sidecar container written in Go—designed from the ground up for Kubernetes Pods without Docker or Docker Compose assumptions.

## Why `kube-vpn`?

General-purpose Docker VPN containers (like Gluetun) assume a Docker/Compose lifecycle where every container restart creates a fresh network namespace, `/etc/resolv.conf` can be rewritten freely, and the root filesystem is writable. In Kubernetes, those assumptions cause repeated operational failures:

| Pain Point in Kubernetes | Gluetun / Docker-first VPNs | `kube-vpn` |
|---|---|---|
| **Shared Pod Network Namespace** | Container restarts leave stale `ip rule` tables & `iptables` rules behind, breaking startup until manually flushed. | Pure-Go netlink & `nftables` reconciliation idempotently cleans stale state on startup and uses a dedicated `inet kube_vpn` table (never flushes CNI/kube-proxy rules). |
| **Dynamic / Rotating Endpoints** | Custom WireGuard configs require literal IPs; `initContainer` DNS hacks go stale when VPN providers rotate IPs, causing CrashLoopBackOff. | Resolves `Endpoint` hostnames natively via Kubernetes CoreDNS (`/etc/resolv.conf`) and automatically re-resolves & updates the peer + firewall **live** on IP rotation—zero restarts. |
| **Read-Only Root Filesystem** | Writes `servers.json`, temp files, and mutates `/etc/resolv.conf`, breaking `readOnlyRootFilesystem: true`. | Single static binary in `FROM scratch`. Zero filesystem writes. Reads `wg0.conf` directly from a read-only Secret mount. |
| **Cluster DNS & Service Discovery** | Hijacks `/etc/resolv.conf` with DoT/Unbound, breaking `*.svc.cluster.local` lookups. | Leaves `/etc/resolv.conf` untouched and automatically routes/allows cluster DNS nameservers over the pod's primary CNI interface. |
| **Native Sidecar Lifecycle** | Race conditions on startup (app leaks before VPN is up) and pod shutdown. | Built for Kubernetes Native Sidecars (`initContainers` + `restartPolicy: Always`) with HTTP `/readyz`, `/healthz`, and `/status` probes. Keeps killswitch active on `SIGTERM` so sibling containers cannot leak while draining. |
| **Kernel WireGuard without `/dev/net/tun`** | Requires `hostPath: /dev/net/tun` even for WireGuard. | Uses native Linux kernel WireGuard via netlink (no `/dev/net/tun` mount needed), with automatic in-memory `wireguard-go` fallback if the kernel module is unavailable. |

## Quick Start (Kubernetes Native Sidecar)

Create a Secret containing a standard `wg0.conf` (hostname or IP endpoints both work):

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-app-vpn
type: Opaque
stringData:
  wg0.conf: |
    [Interface]
    PrivateKey = <your-private-key>
    Address = 10.128.0.2/32
    MTU = 1320

    [Peer]
    PublicKey = <peer-public-key>
    Endpoint = vpn.example.com:51820
    AllowedIPs = 0.0.0.0/0
    PersistentKeepalive = 15
```

Attach `kube-vpn` as a Kubernetes native sidecar (see [examples/kubernetes/qbittorrent-sidecar.yaml](examples/kubernetes/qbittorrent-sidecar.yaml) for a full manifest):

```yaml
spec:
  securityContext:
    sysctls:
      - name: net.ipv4.conf.all.src_valid_mark
        value: "1"
  initContainers:
    - name: kube-vpn
      image: ghcr.io/t0ggl/kube-vpn:latest
      restartPolicy: Always
      securityContext:
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
          add: [NET_ADMIN]
      env:
        - name: BYPASS_SUBNETS
          value: "10.244.0.0/16,10.96.0.0/12"
        - name: POD_INPUT_PORTS
          value: "8080/tcp"
        - name: VPN_INPUT_PORTS
          value: "9514"
      startupProbe:
        httpGet:
          path: /readyz
          port: 9999
        periodSeconds: 2
        failureThreshold: 30
      livenessProbe:
        httpGet:
          path: /healthz
          port: 9999
        periodSeconds: 30
        timeoutSeconds: 5
        failureThreshold: 3
      volumeMounts:
        - name: vpn-config
          mountPath: /etc/wireguard
          readOnly: true
```

> **Note:** On clusters where the node kernel does not include the `wireguard` module, `kube-vpn` automatically falls back to its embedded `wireguard-go` backend; in that case, mount `/dev/net/tun` into the `kube-vpn` container.

## Configuration

All settings are configured via environment variables:

| Variable | Default | Description |
|---|---|---|
| `WG_CONFIG_PATH` | `/etc/wireguard/wg0.conf` | Path to standard WireGuard INI config (read-only). |
| `WG_INTERFACE` | `wg0` | WireGuard network interface name. |
| `WG_BACKEND` | `auto` | `auto` (kernel with userspace fallback), `kernel`, or `userspace`. |
| `WG_FWMARK` | `51820` | Firewall mark and policy routing table ID. |
| `BYPASS_SUBNETS` | *(empty)* | Comma-separated CIDRs/IPs routed directly via the pod's CNI interface (e.g. pod CIDR, service CIDR, LAN, Tailscale). |
| `POD_INPUT_PORTS` | *(empty)* | Comma-separated inbound ports allowed on the pod interface (e.g. `8080/tcp,9090`). Health port is allowed automatically. |
| `VPN_INPUT_PORTS` | *(empty)* | Comma-separated inbound ports allowed over the WireGuard tunnel (e.g. `9514` allows both TCP & UDP; `9514/tcp` for TCP only). |
| `BOOTSTRAP_DNS` | *(`/etc/resolv.conf`)* | Comma-separated DNS server IPs for resolving WireGuard endpoint hostnames. Defaults to pod nameservers (CoreDNS). |
| `HEALTH_ADDR` | `:9999` | Bind address for `/readyz`, `/healthz`, and `/status`. |
| `HEALTH_CHECK_TARGET` | `1.1.1.1:443` | Connectivity check target (`host:port` TCP, `http(s)://...`, or `none`). |
| `HEALTH_CHECK_INTERVAL` | `30s` | Interval between tunnel health probes. |
| `HEALTH_CHECK_TIMEOUT` | `5s` | Timeout per connectivity probe. |
| `ENDPOINT_REFRESH_INTERVAL` | `5m` | Periodic DNS re-resolution interval for hostname endpoints (`0` = only on failure/stale handshake). |
| `HANDSHAKE_STALE_AFTER` | `3m` | Triggers endpoint re-resolution if the latest WireGuard handshake exceeds this age. |
| `KILLSWITCH_ENABLED` | `true` | Enforce atomic `nftables` (`inet kube_vpn`) default-drop killswitch. |
| `KILLSWITCH_KEEP_ON_EXIT` | `true` | Leave `inet kube_vpn` killswitch rules in place on `SIGTERM` so sibling containers cannot leak traffic during pod termination. |
| `LOG_LEVEL` | `info` | Structured JSON log level: `debug`, `info`, `warn`, `error`. |

## HTTP Endpoints

- **`GET /readyz`** — Returns `200 OK` once the killswitch, WireGuard tunnel, and initial connectivity check succeed. Ideal for `startupProbe` and `readinessProbe`.
- **`GET /healthz`** — Returns `200 OK` when the tunnel is healthy, `503 Service Unavailable` otherwise.
- **`GET /status`** — Returns JSON telemetry (backend, interface, readiness, last check, uptime, peer endpoints, last handshake, rx/tx bytes).

## How the Killswitch & Routing Work

1. **Idempotent Startup Cleanup:** Removes any leftover `wg0` interface and `ip rule` entries for table `51820` / `suppress_prefixlength 0` from prior container restarts in the shared Pod netns.
2. **Killswitch First:** Installs an atomic `inet kube_vpn` nftables table with `policy drop` on `input`, `output`, and `forward` **before** resolving endpoints or starting WireGuard.
3. **Zero-Leak Endpoint Rotation:** When a peer's DNS record rotates, `kube-vpn` atomically updates `inet kube_vpn` in a single netlink transaction and updates the WireGuard peer endpoint in-place via `wgctrl` (or in-memory UAPI).
4. **Policy Routing:** Uses `ip rule` priority `51819` (`lookup main suppress_prefixlength 0`) + priority `51820` (`not fwmark 51820 lookup 51820`), preserving the pod's original CNI default route in `main` for encrypted WireGuard packets and explicit `BYPASS_SUBNETS` / CoreDNS routes.

## License

MIT
