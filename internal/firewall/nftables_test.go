package firewall

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/google/nftables"

	"github.com/t0ggl/kube-vpn/internal/config"
)

func TestCIDRMaskBytes(t *testing.T) {
	got := cidrMaskBytes(12, 4)
	want := []byte{0xff, 0xf0, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("cidrMaskBytes(12,4) = %x, want %x", got, want)
	}

	got6 := cidrMaskBytes(64, 16)
	want6 := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(got6, want6) {
		t.Errorf("cidrMaskBytes(64,16) = %x, want %x", got6, want6)
	}
}

func TestBuildRulesCount(t *testing.T) {
	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}
	inChain := &nftables.Chain{Name: "input", Table: tbl}
	outChain := &nftables.Chain{Name: "output", Table: tbl}

	p := Policy{
		WGInterface:  "wg0",
		PodInterface: "eth0",
		FWMARK:       51820,
		Endpoints: []Endpoint{
			{IP: netip.MustParseAddr("139.28.218.237"), Port: 1637},
		},
		BypassSubnets: []netip.Prefix{
			netip.MustParsePrefix("10.244.0.0/16"),
			netip.MustParsePrefix("10.96.0.0/12"),
			netip.MustParsePrefix("0.0.0.0/0"), // must be skipped!
		},
		DNSServers: []netip.Addr{
			netip.MustParseAddr("10.96.0.10"),
		},
		PodInputPorts: []config.PortSpec{
			{Port: 8080, Proto: "tcp"},
			{Port: 9999, Proto: "tcp"},
		},
		VPNInputPorts: []config.PortSpec{
			{Port: 9514, Proto: "both"},
		},
	}

	inRules := buildInputRules(tbl, inChain, p)
	// lo + ct + icmpv6 + 2 pod tcp ports + 2 vpn ports (tcp+udp) = 7
	if len(inRules) != 7 {
		t.Errorf("got %d input rules, want 7", len(inRules))
	}

	outRules := buildOutputRules(tbl, outChain, p)
	// lo + ct + wg0 + 1 endpoint + 2 dns (udp+tcp) + 2 bypass (0.0.0.0/0 skipped) = 8
	if len(outRules) != 8 {
		t.Errorf("got %d output rules, want 8", len(outRules))
	}
}
