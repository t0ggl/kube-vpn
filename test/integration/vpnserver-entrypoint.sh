#!/bin/sh
set -eu

# Create WireGuard server interface
ip link add wg0 type wireguard
ip addr add "${WG_SERVER_ADDR:-10.200.0.1/24}" dev wg0

printf "%s" "$WG_SERVER_PRIVATE_KEY" > /tmp/server.key
wg set wg0 \
  listen-port "${WG_LISTEN_PORT:-51820}" \
  private-key /tmp/server.key \
  peer "$WG_CLIENT_PUBLIC_KEY" \
  allowed-ips "${WG_CLIENT_ALLOWED_IPS:-10.200.0.2/32}"
rm -f /tmp/server.key

ip link set up dev wg0

# Enable IPv4 forwarding and masquerade VPN client traffic out to the upstream network.
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

nft -f - <<EOF
table ip nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr 10.200.0.0/24 oifname != "wg0" masquerade
  }
}
EOF

echo "wireguard test server ready on port ${WG_LISTEN_PORT:-51820}"
exec sleep infinity
