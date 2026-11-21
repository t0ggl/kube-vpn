package firewall

import (
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/t0ggl/kube-vpn/internal/config"
)

const TableName = "kube_vpn"

// Endpoint represents a resolved WireGuard peer UDP destination.
type Endpoint struct {
	IP   netip.Addr
	Port uint16
}

// Policy describes the complete desired state of the nftables killswitch.
type Policy struct {
	WGInterface   string
	PodInterface  string
	FWMARK        uint32
	Endpoints     []Endpoint
	BypassSubnets []netip.Prefix
	DNSServers    []netip.Addr
	PodInputPorts []config.PortSpec
	VPNInputPorts []config.PortSpec
}

// Manager manages the dedicated `inet kube_vpn` nftables table.
type Manager struct {
	conn *nftables.Conn
}

// NewManager creates an nftables netlink connection.
func NewManager() (*Manager, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("open nftables netlink connection: %w", err)
	}
	return &Manager{conn: c}, nil
}

// Apply atomically replaces the `inet kube_vpn` nftables table with the given policy.
// Because AddTable + FlushTable + rules are committed in a single netlink batch,
// there is zero window where the killswitch is inactive—even during endpoint rotation.
func (m *Manager) Apply(p Policy) error {
	if p.WGInterface == "" || p.PodInterface == "" {
		return fmt.Errorf("WGInterface and PodInterface are required")
	}

	// Ensure table exists, then flush all its chains/rules atomically within this batch.
	table := m.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   TableName,
	})
	m.conn.FlushTable(table)

	drop := nftables.ChainPolicyDrop

	inChain := m.conn.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &drop,
	})

	outChain := m.conn.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &drop,
	})

	_ = m.conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &drop,
	})

	for _, rule := range buildInputRules(table, inChain, p) {
		m.conn.AddRule(rule)
	}
	for _, rule := range buildOutputRules(table, outChain, p) {
		m.conn.AddRule(rule)
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("commit nftables killswitch policy: %w", err)
	}
	return nil
}

// Delete removes the `inet kube_vpn` table if it exists.
func (m *Manager) Delete() error {
	tables, err := m.conn.ListTables()
	if err != nil {
		return fmt.Errorf("list nftables tables: %w", err)
	}
	for _, t := range tables {
		if t.Family == nftables.TableFamilyINet && t.Name == TableName {
			m.conn.DelTable(t)
			if err := m.conn.Flush(); err != nil {
				return fmt.Errorf("delete nftables table %s: %w", TableName, err)
			}
			return nil
		}
	}
	return nil
}

func buildInputRules(table *nftables.Table, chain *nftables.Chain, p Policy) []*nftables.Rule {
	var rules []*nftables.Rule
	add := func(exprs ...expr.Any) {
		exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
		rules = append(rules, &nftables.Rule{Table: table, Chain: chain, Exprs: exprs})
	}

	// 1. Always allow loopback (container-to-container localhost inside the Pod).
	add(matchIifName("lo")...)

	// 2. Always allow established/related return traffic.
	add(matchCtEstablishedRelated()...)

	// 3. Allow ICMPv6 neighbor discovery / ICMP essentials on pod interface if needed.
	add(append(matchIifName(p.PodInterface), matchL4Proto(unix.IPPROTO_ICMPV6)...)...)

	// 4. Allow configured Pod/Cluster inbound ports on the primary pod interface
	//    (WebUI, kubelet probes, health server).
	for _, ps := range p.PodInputPorts {
		for _, proto := range expandProto(ps.Proto) {
			e := append([]expr.Any{}, matchIifName(p.PodInterface)...)
			e = append(e, matchL4DstPort(proto, ps.Port)...)
			add(e...)
		}
	}

	// 5. Allow configured inbound VPN ports over the WireGuard tunnel (e.g. BitTorrent peer port).
	for _, ps := range p.VPNInputPorts {
		for _, proto := range expandProto(ps.Proto) {
			e := append([]expr.Any{}, matchIifName(p.WGInterface)...)
			e = append(e, matchL4DstPort(proto, ps.Port)...)
			add(e...)
		}
	}

	return rules
}

func buildOutputRules(table *nftables.Table, chain *nftables.Chain, p Policy) []*nftables.Rule {
	var rules []*nftables.Rule
	add := func(exprs ...expr.Any) {
		exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictAccept})
		rules = append(rules, &nftables.Rule{Table: table, Chain: chain, Exprs: exprs})
	}

	// 1. Always allow loopback.
	add(matchOifName("lo")...)

	// 2. Always allow established/related return traffic (e.g. HTTP responses to PodInputPorts).
	add(matchCtEstablishedRelated()...)

	// 3. Allow ALL outbound traffic going through the WireGuard tunnel interface.
	add(matchOifName(p.WGInterface)...)

	// 4. Allow encrypted WireGuard UDP packets to each resolved peer endpoint on the pod interface.
	//    When FWMARK is set, also require the packet to carry the WireGuard fwmark so
	//    nothing else in the pod can reach the endpoint unencrypted.
	for _, ep := range p.Endpoints {
		e := append([]expr.Any{}, matchOifName(p.PodInterface)...)
		if p.FWMARK != 0 {
			e = append(e, matchFWMARK(p.FWMARK)...)
		}
		e = append(e, matchDstCIDR(netip.PrefixFrom(ep.IP.Unmap(), ep.IP.Unmap().BitLen()))...)
		e = append(e, matchL4DstPort(unix.IPPROTO_UDP, ep.Port)...)
		add(e...)
	}

	// 5. Allow DNS (UDP & TCP port 53) to Kubernetes cluster DNS / bootstrap DNS servers
	//    so CoreDNS service discovery (*.svc.cluster.local) and dynamic WireGuard endpoint
	//    re-resolution always work without leaking external traffic.
	for _, dnsIP := range p.DNSServers {
		prefix := netip.PrefixFrom(dnsIP.Unmap(), dnsIP.Unmap().BitLen())
		for _, proto := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
			e := append([]expr.Any{}, matchOifName(p.PodInterface)...)
			e = append(e, matchDstCIDR(prefix)...)
			e = append(e, matchL4DstPort(proto, 53)...)
			add(e...)
		}
	}

	// 6. Allow outbound traffic to explicit Kubernetes/LAN/Tailscale bypass subnets.
	for _, subnet := range p.BypassSubnets {
		if subnet.Bits() == 0 {
			continue
		}
		e := append([]expr.Any{}, matchOifName(p.PodInterface)...)
		e = append(e, matchDstCIDR(subnet.Masked())...)
		add(e...)
	}

	return rules
}

func ifnameBytes(name string) []byte {
	b := make([]byte, len(name)+1)
	copy(b, name)
	return b
}

func matchIifName(name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameBytes(name)},
	}
}

func matchOifName(name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameBytes(name)},
	}
}

func matchCtEstablishedRelated() []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, SourceRegister: false, Key: expr.CtKeySTATE},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
	}
}

func matchFWMARK(mark uint32) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(mark)},
	}
}

func matchL4Proto(proto byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
	}
}

func matchL4DstPort(proto byte, port uint16) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2, // destination port offset for both TCP and UDP
			Len:          2,
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
	}
}

func matchDstCIDR(prefix netip.Prefix) []expr.Any {
	prefix = prefix.Masked()
	addr := prefix.Addr().Unmap()
	if addr.Is4() {
		a4 := addr.As4()
		exprs := []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16, // IPv4 destination address offset
				Len:          4,
			},
		}
		if prefix.Bits() < 32 {
			mask := cidrMaskBytes(prefix.Bits(), 4)
			exprs = append(exprs, &expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           mask,
				Xor:            make([]byte, 4),
			})
		}
		exprs = append(exprs, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: a4[:]})
		return exprs
	}

	a16 := addr.As16()
	exprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       24, // IPv6 destination address offset
			Len:          16,
		},
	}
	if prefix.Bits() < 128 {
		mask := cidrMaskBytes(prefix.Bits(), 16)
		exprs = append(exprs, &expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            16,
			Mask:           mask,
			Xor:            make([]byte, 16),
		})
	}
	exprs = append(exprs, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: a16[:]})
	return exprs
}

func cidrMaskBytes(bits, byteLen int) []byte {
	mask := make([]byte, byteLen)
	for i := 0; i < bits && i < byteLen*8; i++ {
		mask[i/8] |= 1 << (7 - uint(i%8))
	}
	return mask
}

func expandProto(p string) []byte {
	switch p {
	case "tcp":
		return []byte{unix.IPPROTO_TCP}
	case "udp":
		return []byte{unix.IPPROTO_UDP}
	default:
		return []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP}
	}
}
