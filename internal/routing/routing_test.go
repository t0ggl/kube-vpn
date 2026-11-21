package routing

import (
	"net"
	"net/netip"
	"testing"
)

func TestPrefixToIPNet(t *testing.T) {
	p4 := netip.MustParsePrefix("10.128.0.2/32")
	n4 := prefixToIPNet(p4)
	if n4.String() != "10.128.0.2/32" {
		t.Errorf("got %s, want 10.128.0.2/32", n4.String())
	}

	p6 := netip.MustParsePrefix("fd7d:76ee:e68f::2/128")
	n6 := prefixToIPNet(p6)
	if n6.String() != "fd7d:76ee:e68f::2/128" {
		t.Errorf("got %s, want fd7d:76ee:e68f::2/128", n6.String())
	}
}

func TestIsDefaultDst(t *testing.T) {
	if !isDefaultDst(nil) {
		t.Errorf("nil dst should be default")
	}
	if !isDefaultDst(&net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}) {
		t.Errorf("0.0.0.0/0 should be default")
	}
	if isDefaultDst(&net.IPNet{IP: net.ParseIP("10.96.0.0"), Mask: net.CIDRMask(12, 32)}) {
		t.Errorf("10.96.0.0/12 should not be default")
	}
}

func TestPodNetworkPrimaryInterface(t *testing.T) {
	pn := &PodNetwork{V4: &DefaultRoute{LinkName: "eth0"}}
	if pn.PrimaryInterface() != "eth0" {
		t.Errorf("got %s, want eth0", pn.PrimaryInterface())
	}
	empty := &PodNetwork{}
	if empty.PrimaryInterface() != "eth0" {
		t.Errorf("empty fallback got %s, want eth0", empty.PrimaryInterface())
	}
}

func TestRulePrioritiesBeforeMain(t *testing.T) {
	if RulePrioritySuppressMain >= RulePriorityVPNTable {
		t.Errorf("RulePrioritySuppressMain (%d) must be < RulePriorityVPNTable (%d)", RulePrioritySuppressMain, RulePriorityVPNTable)
	}
	if RulePriorityVPNTable >= 32766 {
		t.Errorf("RulePriorityVPNTable (%d) must be < Linux default main rule priority (32766)", RulePriorityVPNTable)
	}
}
