package routing

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// RulePrioritySuppressMain is the ip rule priority for `lookup main suppress_prefixlength 0`.
	RulePrioritySuppressMain = 51819
	// RulePriorityVPNTable is the ip rule priority for `not fwmark <mark> lookup <table>`.
	RulePriorityVPNTable = 51820
)

// DefaultRoute captures the pod's primary CNI interface and default gateway.
type DefaultRoute struct {
	LinkIndex int
	LinkName  string
	Gateway   net.IP
	Flags     int
}

// PodNetwork holds the detected IPv4 and optional IPv6 primary pod network info.
type PodNetwork struct {
	V4 *DefaultRoute
	V6 *DefaultRoute
}

// PrimaryInterface returns the pod's main CNI interface name (typically eth0).
func (p *PodNetwork) PrimaryInterface() string {
	if p.V4 != nil && p.V4.LinkName != "" {
		return p.V4.LinkName
	}
	if p.V6 != nil && p.V6.LinkName != "" {
		return p.V6.LinkName
	}
	return "eth0"
}

// DetectPodNetwork inspects the main routing table to find the pod's primary
// CNI interface and default gateway (ignoring the WireGuard interface if stale).
func DetectPodNetwork(wgIface string) (*PodNetwork, error) {
	pn := &PodNetwork{}

	if r4, err := findDefaultRoute(netlink.FAMILY_V4, wgIface); err == nil {
		pn.V4 = r4
	}
	if r6, err := findDefaultRoute(netlink.FAMILY_V6, wgIface); err == nil {
		pn.V6 = r6
	}

	if pn.V4 == nil && pn.V6 == nil {
		return nil, fmt.Errorf("no default IPv4 or IPv6 route found in main routing table")
	}
	return pn, nil
}

func findDefaultRoute(family int, excludeIface string) (*DefaultRoute, error) {
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	for _, r := range routes {
		if !isDefaultDst(r.Dst) {
			continue
		}
		link, err := netlink.LinkByIndex(r.LinkIndex)
		if err != nil {
			continue
		}
		if link.Attrs().Name == excludeIface {
			continue
		}
		return &DefaultRoute{
			LinkIndex: r.LinkIndex,
			LinkName:  link.Attrs().Name,
			Gateway:   r.Gw,
			Flags:     r.Flags,
		}, nil
	}
	return nil, fmt.Errorf("no default route for family %d", family)
}

func isDefaultDst(dst *net.IPNet) bool {
	if dst == nil {
		return true
	}
	ones, _ := dst.Mask.Size()
	return ones == 0
}

// CleanupStale idempotently removes leftover WireGuard interface, policy routing
// rules, and VPN table routes from a previous container run in the same Pod netns.
func CleanupStale(wgIface string, fwmark uint32) error {
	table := int(fwmark)

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			continue
		}
		for _, r := range rules {
			isOurTable := r.Table == table
			isOurSuppress := r.Table == unix.RT_TABLE_MAIN && r.SuppressPrefixlen == 0 && r.Priority == RulePrioritySuppressMain
			isOurPriority := r.Priority == RulePriorityVPNTable
			if isOurTable || isOurSuppress || isOurPriority {
				ruleCopy := r
				_ = netlink.RuleDel(&ruleCopy)
			}
		}
	}

	if link, err := netlink.LinkByName(wgIface); err == nil {
		if delErr := netlink.LinkDel(link); delErr != nil && !errors.Is(delErr, syscall.ENODEV) {
			return fmt.Errorf("delete stale interface %s: %w", wgIface, delErr)
		}
	}

	return nil
}

// ConfigureInterface assigns IP addresses and MTU to the WireGuard link and brings it up.
func ConfigureInterface(ifaceName string, addrs []netip.Prefix, mtu int) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("find interface %s: %w", ifaceName, err)
	}

	if mtu > 0 {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return fmt.Errorf("set MTU %d on %s: %w", mtu, ifaceName, err)
		}
	}

	for _, p := range addrs {
		nlAddr := &netlink.Addr{IPNet: prefixToIPNet(p)}
		if err := netlink.AddrReplace(link, nlAddr); err != nil {
			return fmt.Errorf("add address %s to %s: %w", p, ifaceName, err)
		}
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring up %s: %w", ifaceName, err)
	}

	return nil
}

// SetupPolicyRouting installs the WireGuard default routes in table <fwmark>,
// policy routing rules (suppress_prefixlength 0 + not fwmark), and explicit
// bypass routes in the main table via the pod's original CNI gateway.
func SetupPolicyRouting(ifaceName string, fwmark uint32, podNet *PodNetwork, hasV4, hasV6 bool, bypassSubnets []netip.Prefix) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("find interface %s: %w", ifaceName, err)
	}

	table := int(fwmark)

	// 1. Add explicit bypass routes in main table so they are matched by
	//    `lookup main suppress_prefixlength 0` and exit via the pod's CNI interface.
	for _, prefix := range bypassSubnets {
		if err := addBypassRoute(prefix, podNet); err != nil {
			return fmt.Errorf("add bypass route %s: %w", prefix, err)
		}
	}

	// 2. Add default route(s) via wg0 in our dedicated routing table.
	if hasV4 {
		r4 := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			Table:     table,
		}
		if err := netlink.RouteReplace(r4); err != nil {
			return fmt.Errorf("add IPv4 VPN default route: %w", err)
		}
		if err := installPolicyRules(netlink.FAMILY_V4, fwmark); err != nil {
			return fmt.Errorf("install IPv4 policy rules: %w", err)
		}
	}

	if hasV6 {
		r6 := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
			Table:     table,
		}
		if err := netlink.RouteReplace(r6); err != nil {
			return fmt.Errorf("add IPv6 VPN default route: %w", err)
		}
		if err := installPolicyRules(netlink.FAMILY_V6, fwmark); err != nil {
			return fmt.Errorf("install IPv6 policy rules: %w", err)
		}
	}

	return nil
}

func installPolicyRules(family int, fwmark uint32) error {
	// Priority 51819: lookup main suppress_prefixlength 0
	// Matches all specific routes in main (pod subnet, CNI gateway, bypass subnets,
	// cluster DNS) while ignoring main's default route (0.0.0.0/0 or ::/0).
	suppressRule := netlink.NewRule()
	suppressRule.Family = family
	suppressRule.Priority = RulePrioritySuppressMain
	suppressRule.Table = unix.RT_TABLE_MAIN
	suppressRule.SuppressPrefixlen = 0
	if err := netlink.RuleAdd(suppressRule); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("add suppress_prefixlength rule: %w", err)
	}

	// Priority 51820: not fwmark <fwmark> lookup <fwmark>
	// Routes all non-WireGuard traffic through the VPN table. WireGuard's own
	// encrypted UDP packets carry fwmark and fall through to main's default route.
	vpnRule := netlink.NewRule()
	vpnRule.Family = family
	vpnRule.Priority = RulePriorityVPNTable
	vpnRule.Mark = fwmark
	vpnRule.Invert = true
	vpnRule.Table = int(fwmark)
	if err := netlink.RuleAdd(vpnRule); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("add vpn fwmark rule: %w", err)
	}

	return nil
}

func addBypassRoute(prefix netip.Prefix, podNet *PodNetwork) error {
	prefix = prefix.Masked()
	// Never install a /0 bypass route (that would defeat the VPN).
	if prefix.Bits() == 0 {
		return nil
	}

	var def *DefaultRoute
	if prefix.Addr().Is4() {
		def = podNet.V4
	} else {
		def = podNet.V6
	}
	if def == nil {
		// Pod does not have connectivity for this address family; skip cleanly.
		return nil
	}

	route := &netlink.Route{
		LinkIndex: def.LinkIndex,
		Dst:       prefixToIPNet(prefix),
		Gw:        def.Gateway,
		Table:     unix.RT_TABLE_MAIN,
	}
	if def.Gateway != nil && (def.Flags&int(netlink.FLAG_ONLINK) != 0) {
		route.Flags = int(netlink.FLAG_ONLINK)
	}

	if err := netlink.RouteReplace(route); err != nil && !errors.Is(err, syscall.EEXIST) {
		return err
	}
	return nil
}

// PrefixToIPNet converts a netip.Prefix to a *net.IPNet preserving its host IP.
func prefixToIPNet(p netip.Prefix) *net.IPNet {
	ip := net.IP(p.Addr().AsSlice())
	bits := p.Addr().BitLen()
	return &net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(p.Bits(), bits),
	}
}
