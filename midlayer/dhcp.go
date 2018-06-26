package midlayer

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/ipv4"

	"github.com/digitalrebar/logger"
	"github.com/digitalrebar/pinger"
	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	dhcp "github.com/krolaw/dhcp4"
)

type StrategyFunc func(p dhcp.Packet, options dhcp.Options) string

type Strategy struct {
	Name     string
	GenToken StrategyFunc
}

func MacStrategy(p dhcp.Packet, options dhcp.Options) string {
	return p.CHAddr().String()
}

// DhcpRequest records all the information needed to handle a single
// in-flight DHCP request.  One of these is created for every incoming
// DHCP packet.
type DhcpRequest struct {
	logger.Logger
	idxMap                map[int][]*net.IPNet
	nameMap               map[int]string
	srcAddr               net.Addr
	defaultIP, nextServer net.IP
	cm                    *ipv4.ControlMessage
	pkt                   dhcp.Packet
	pktOpts, outOpts      dhcp.Options
	pinger                pinger.Pinger
	handler               *DhcpHandler
	lPort                 int
	duration              time.Duration
	offerPXE              bool
	start                 time.Time
}

// xid is a helper function that returns the xid of the request we are
// working on in a format suitable for inclusion in a log message.
func (dhr *DhcpRequest) xid() string {
	return fmt.Sprintf("xid 0x%x", binary.BigEndian.Uint32(dhr.pkt.XId()))
}

// ifname returns the name of the network interface that is handling
// this DHCP message.  We always attempt to send the response out the
// same interface it came in on.
func (dhr *DhcpRequest) ifname() string {
	return dhr.nameMap[dhr.cm.IfIndex]
}

// fill populates the DhcpRequest with the current known state of the
// network interfaces opn the system.  We do this on a per-request
// basis to ensure that dr-provision operates correctly in the face of
// a dynamic networking environment.
func (dhr *DhcpRequest) fill() *DhcpRequest {
	dhr.idxMap = map[int][]*net.IPNet{}
	dhr.nameMap = map[int]string{}
	ifs, err := net.Interfaces()
	if err != nil {
		dhr.Errorf("Cannot fetch local interface map: %v", err)
		return nil
	}
	for _, iface := range ifs {
		addrs, err := iface.Addrs()
		if err != nil {
			dhr.Errorf("Failed to fetch addresses for %s: %v", iface.Name, err)
			continue
		}
		toAdd := []*net.IPNet{}
		for idx := range addrs {
			addr, ok := addrs[idx].(*net.IPNet)
			if ok {
				toAdd = append(toAdd, addr)
			}
		}
		dhr.idxMap[iface.Index] = toAdd
		dhr.nameMap[iface.Index] = iface.Name
	}
	return dhr
}

// proxyOnly returns whether the DhcpHandler that created this request
// lives on the binl port.
func (dhr *DhcpRequest) binlOnly() bool {
	return dhr.handler.binlOnly
}

// Request is a shorthand function for creating a RequestTracker to
// interact with the backend.
func (dhr *DhcpRequest) Request(locks ...string) *backend.RequestTracker {
	return dhr.handler.bk.Request(dhr.Logger, locks...)
}

// listenAddrs gets all of the addresses the DHCP server is currently
// listening to.  This includes netmasks.
func (dhr *DhcpRequest) listenAddrs() []*net.IPNet {
	addrs, ok := dhr.idxMap[dhr.cm.IfIndex]
	if !ok {
		return []*net.IPNet{}
	}
	return addrs
}

// listenIPs returns the IP addresses the DHCP server is listening to.
func (dhr *DhcpRequest) listenIPs() []net.IP {
	addrs := dhr.listenAddrs()
	res := make([]net.IP, len(addrs))
	for i := range addrs {
		res[i] = addrs[i].IP
	}
	return res
}

// isOneOfMyAddrs returns whether or not the passed IP address is an
// address the DHCP server is currently listening to.
func (dhr *DhcpRequest) isOneOfMyAddrs(srcAddr net.IP) bool {
	for _, addrs := range dhr.idxMap {
		for _, addr := range addrs {
			if addr.IP.Equal(srcAddr) {
				return true
			}
		}
	}
	return false
}

// respondFrom determines what local IP address we should appear to
// respond from.  It is usually used to determine what the server ID
// for any particular DHCP response should be.
func (dhr *DhcpRequest) respondFrom(testAddr net.IP) net.IP {
	addrs := dhr.listenAddrs()
	for _, addr := range addrs {
		if addr.Contains(testAddr) {
			return addr.IP.To4()
		}
	}
	// Well, this sucks.  Return the first address we listen on for this
	// interface.
	if len(addrs) > 0 {
		dhr.Warnf("No matching subnet, will respond to %s from %s", testAddr, addrs[0].IP)
		return addrs[0].IP.To4()
	}
	// Well, this really sucks.  Return our global listen-on address
	if dhr.defaultIP != nil {
		dhr.Errorf("No address on interface index %d, using our static IP %s", dhr.cm.IfIndex, dhr.defaultIP)
		return dhr.defaultIP
	}
	// Last resport fallback is to use the IP address the default route
	// is associated with.
	addr := backend.DefaultIP(dhr.Logger)
	dhr.Errorf("No address on interface index %d, using IP with default route %v", dhr.cm.IfIndex, addr)
	return addr
}

// listenOn determines whether the passed IP address is one we are
// listening on.
func (dhr *DhcpRequest) listenOn(testAddr net.IP) bool {
	for _, addr := range dhr.listenIPs() {
		if addr.Equal(testAddr) {
			return true
		}
	}
	return false
}

//option:code:175 val:“177,5,1,128,134,16,14,33,1,1,16,1,2,39,1,1,235,3,1,0,0,23,1,1,21,1,1,19,1,1”
type ipxeOpts struct {
	// base options
	prio    int8 // code 1 = int8
	keepsan bool // code 8 = uint8
	skipsan bool // code 9 = uint8
	// feature indicators
	pxeext    byte // code 16 = uint8
	biosdrive byte // code 189 = unsigned integer 8;
	iscsi     bool // code 17 = uint8
	aoe       bool // code 18 = uint8
	http      bool // code 19 = uint8
	https     bool // code 20 = uint8
	tftp      bool // code 21 = uint8
	ftp       bool // code 22 = uint8
	dns       bool // code 23 = uint8
	bzimage   bool // code 24 = uint8
	multiboot bool // code 25 = uint8
	slam      bool // code 26 = uint8
	srp       bool // code 27 = uint8
	nbi       bool // code 32 = uint8
	pxe       bool // code 33 = uint8
	elf       bool // code 34 = uint8
	comboot   bool // code 35 = uint8
	efi       bool // code 36 = uint8
	fcoe      bool // code 37 = uint8
	vlan      bool // code 38 = uint8
	menu      bool // code 39 = uint8
	sdi       bool // code 40 = uint8
	nfs       bool // code 41 = uint8
	nopxedhcp bool // code 176 = uint 8;
	// strings
	syslogs           string // code 85 = string;
	cert              string // code 91 = string;
	privkey           string // code 92 = string;
	crosscert         string // code 93 = string;
	busid             string // code 177 = string;
	sanfilename       string // code 188 = string;
	username          string // code 190 = string;
	password          string // code 191 = string;
	reverseusername   string // code 192 = string;
	reversepassword   string // code 193 = string;
	version           string // code 235 = string;
	iscsiinitiatoriqn string // code 203 = string;
}

func (dhr *DhcpRequest) ipxeIsSane(arch uint) bool {
	opts := parseIpxeOpts(dhr)
	if !opts.http {
		dhr.Warnf("Incoming iPXE does not support http")
		return false
	}
	if arch == 0 {
		if !opts.pxe {
			dhr.Errorf("Incoming iPXE for arch %d does not support pxe. This should not happen", arch)
			return false
		}
		if !opts.bzimage {
			dhr.Warnf("Incoming iPXE does not support bzImage")
			return false
		}
	}
	if arch != 0 && !opts.efi {
		dhr.Errorf("Incoming iPXE for arch %d does not support efi. This should not happen", arch)
		return false
	}
	dhr.Infof("Incoming iPXE request is sane")
	return true
}

func btob(b []byte) bool {
	return b[0] != 0
}

func parseIpxeOpts(dhr *DhcpRequest) (res ipxeOpts) {
	opts := dhr.pktOpts[175]
	res = ipxeOpts{}
	if opts == nil || len(opts) == 0 {
		return res
	}
	for len(opts) > 2 {
		code := opts[0]
		codeLen := int(opts[1])
		if len(opts[2:]) < codeLen {
			return
		}
		opts = opts[2:]
		val := opts[:codeLen]
		dhr.Debugf("iPXE opt %d (len%d): %v", code, codeLen, val)
		opts = opts[codeLen:]
		switch code {
		// base first
		case 1:
			res.prio = int8(val[0])
		// byte vals
		case 16:
			res.pxeext = val[0]
		case 189:
			res.biosdrive = val[0]
			// boolean values
		case 176:
			res.nopxedhcp = btob(val)
		case 8:
			res.keepsan = btob(val)
		case 9:
			res.skipsan = btob(val)
		case 17:
			res.iscsi = btob(val)
		case 18:
			res.aoe = btob(val)
		case 19:
			res.http = btob(val)
		case 20:
			res.https = btob(val)
		case 21:
			res.tftp = btob(val)
		case 22:
			res.ftp = btob(val)
		case 23:
			res.dns = btob(val)
		case 24:
			res.bzimage = btob(val)
		case 25:
			res.multiboot = btob(val)
		case 26:
			res.slam = btob(val)
		case 27:
			res.srp = btob(val)
		case 32:
			res.nbi = btob(val)
		case 33:
			res.pxe = btob(val)
		case 34:
			res.elf = btob(val)
		case 35:
			res.comboot = btob(val)
		case 36:
			res.efi = btob(val)
		case 37:
			res.fcoe = btob(val)
		case 38:
			res.vlan = btob(val)
		case 39:
			res.menu = btob(val)
		case 40:
			res.sdi = btob(val)
		case 41:
			res.nfs = btob(val)
			// string values
		case 85:
			res.syslogs = string(val)
		case 91:
			res.cert = string(val)
		case 92:
			res.privkey = string(val)
		case 93:
			res.crosscert = string(val)
		case 177:
			res.busid = string(val)
		case 188:
			res.sanfilename = string(val)
		case 190:
			res.username = string(val)
		case 191:
			res.password = string(val)
		case 192:
			res.reverseusername = string(val)
		case 193:
			res.reversepassword = string(val)
		case 203:
			res.iscsiinitiatoriqn = string(val)
		case 235:
			res.version = string(val)
		}
	}
	return res
}

// coalesceOptions is responsible for building the options we will
// reply with, as well as figuring out whether or not we should offer
// PXE and TFTP file name options in the outgoing packet.
func (dhr *DhcpRequest) coalesceOptions(
	l *backend.Lease,
	s *backend.Subnet,
	r *backend.Reservation) {
	dhr.offerPXE = true
	dhr.outOpts = dhcp.Options{}
	// Compile and render options from the subnet and the reservation first.
	srcOpts := map[int]string{}
	for c, v := range dhr.pktOpts {
		opt := &models.DhcpOption{Code: byte(c)}
		opt.FillFromPacketOpt(v)
		srcOpts[int(c)] = opt.Value
	}
	if r != nil {
		for _, opt := range r.Options {
			if opt.Value == "" {
				if dhcp.OptionCode(opt.Code) != dhcp.OptionBootFileName {
					dhr.Debugf("Ignoring DHCP option %d with zero-length value", opt.Code)
					continue
				}
			}
			c, v, err := opt.RenderToDHCP(srcOpts)
			if err != nil {
				dhr.Errorf("Failed to render option %v: %v, %v", opt.Code, opt.Value, err)
				continue
			}
			dhr.outOpts[dhcp.OptionCode(c)] = v
		}
	}
	if s != nil {
		for _, opt := range s.Options {
			if dhr.outOpts[dhcp.OptionCode(opt.Code)] != nil {
				continue
			}
			if opt.Value == "" {
				dhr.Debugf("Ignoring DHCP option %d with zero-length value", opt.Code)
				continue
			}
			c, v, err := opt.RenderToDHCP(srcOpts)
			if err != nil {
				dhr.Errorf("Failed to render option %v: %v, %v", opt.Code, opt.Value, err)
				continue
			}
			dhr.outOpts[dhcp.OptionCode(c)] = v
		}
		if s.NextServer != nil && s.NextServer.IsGlobalUnicast() {
			dhr.nextServer = s.NextServer
		}
	}
	if r != nil && r.NextServer != nil && r.NextServer.IsGlobalUnicast() {
		dhr.nextServer = r.NextServer
	}
	if nextServer := dhr.nextServer.To4(); nextServer != nil && !nextServer.IsUnspecified() {
		dhr.nextServer = nextServer
		dhr.outOpts[dhcp.OptionTFTPServerName] = []byte(dhr.nextServer.String())
	} else {
		dhr.nextServer = nil
	}
	// If the incoming packet does not want a filename, it does not want
	// to PXE boot.
	if vals, ok := dhr.pktOpts[dhcp.OptionParameterRequestList]; !ok ||
		bytes.IndexByte(vals, byte(dhcp.OptionBootFileName)) == -1 {
		dhr.offerPXE = false
		return
	}
	// If the incoming packet does not have a PXEClient vendor class identifier,
	// it does not want to PXE boot.
	if val, ok := dhr.pktOpts[dhcp.OptionVendorClassIdentifier]; !ok ||
		!strings.HasPrefix(string(val), "PXEClient") {
		dhr.offerPXE = false
		return
	}
	// If we have a dhcp.OptionBootFileName set to "", a reservation told us
	// to not PXE boot.
	if val, ok := dhr.outOpts[dhcp.OptionBootFileName]; ok && len(val) == 0 {
		dhr.offerPXE = false
		return
	}
	// If the subnet is unmanaged, we never want machines to PXE boot from it.
	if s != nil && s.Unmanaged {
		dhr.offerPXE = false
		return
	}
	// Otherwise, assume we will want to offer PXE information unless
	// we can tie the incoming packet to a machine we know about and we
	// can determine that we should not attempt to PXE boot it.
	var machine *backend.Machine
	var bootEnv *backend.BootEnv
	rt := dhr.Request(machine.Locks("update")...)
	rt.Do(func(d backend.Stores) {
		machine = rt.MachineForMac(dhr.pkt.CHAddr().String())
		if machine == nil {
			m2 := rt.FindByIndex("machines", machine.Indexes()["Address"], l.Addr.String())
			if m2 != nil {
				machine = backend.AsMachine(m2)
			}
		}
		if machine == nil {
			// No machine known for this MAC address or IP address.  It can
			// PXE boot if it wants.
			return
		}
		if bk := rt.Find("bootenvs", machine.BootEnv); bk != nil {
			bootEnv = backend.AsBootEnv(bk)
		} else {
			// This should never happen, but if it does then Something Bad
			// happened, and we will allow it to PXE boot if it wants.
			rt.Errorf("%s: Machine %s refers to missing BootEnv %s",
				dhr.xid(),
				machine.UUID(),
				machine.BootEnv)
			return
		}
		if !bootEnv.NetBoot() {
			// We found a machine, and the bootenv it is set to does not
			// want to net boot.  We should not let it PXE boot from us.
			dhr.offerPXE = false
			return
		}
		if l.Addr.IsUnspecified() {
			return
		}
		// We want the machine to PXE boot, and we know what address it is
		// getting.  However, that address may not be one that we are
		// currently rendering templates for.  Check to see if we need to
		// update the machine's address of record.
		machineSave := !machine.Address.Equal(l.Addr)
		others, err := index.All(
			index.Sort(machine.Indexes()["Address"]),
			index.Eq(l.Addr.String()))(rt.Index("machines"))
		if err == nil && others.Count() > 0 {
			for _, other := range others.Items() {
				if other.Key() == machine.UUID() {
					continue
				}
				oMachine := backend.AsMachine(other)
				rt.Warnf("Machine %s also has address %s, which we are handing out to %s", oMachine.UUID(), l.Addr, machine.UUID())
				rt.Warnf("Setting machine %s address to all zeros", oMachine.UUID())
				oMachine.Address = net.IPv4(0, 0, 0, 0)
				rt.Save(oMachine)
			}
		}
		if machineSave {
			rt.Warnf("%s: Updating machine %s address from %s to %s", dhr.xid(), machine.UUID(), machine.Address, l.Addr)
			machine.Address = l.Addr
			rt.Save(machine)
		}
	})
	if !dhr.offerPXE {
		return
	}
	// Fill out default options for BootFileName and TFTPServerName
	if _, ok := dhr.outOpts[dhcp.OptionBootFileName]; !ok {
		fname := ""
		var arch uint
		if val, ok := dhr.pktOpts[dhcp.OptionClientArchitecture]; ok {
			arch = uint(val[0])<<8 + uint(val[1])
		}
		if val, ok := dhr.pktOpts[dhcp.OptionUserClass]; ok &&
			string(val) == "iPXE" &&
			dhr.ipxeIsSane(arch) {
			fname = "default.ipxe"
		} else {
			switch arch {
			case 0:
				fname = "lpxelinux.0"
			case 7, 9:
				fname = "ipxe.efi"
			case 6:
				dhr.Errorf("dr-provision does not support 32 bit EFI systems")
			case 10:
				dhr.Errorf("dr-provision does not support 32 bit ARM EFI systems")
			case 11:
				dhr.Errorf("dr-provision does not support 64 bit ARM EFI systems")
			default:
				dhr.Errorf("Unknown client arch %d: cannot PXE boot it remotely", arch)
			}
		}
		if fname == "" {
			dhr.offerPXE = false
			return
		}
		dhr.outOpts[dhcp.OptionBootFileName] = []byte(fname)
	}
}

// buildReply is the general purpose function for building the
// appropriate response to the DHCP packet we are currently handling.
func (dhr *DhcpRequest) buildReply(
	mt dhcp.MessageType,
	serverID,
	yAddr net.IP) dhcp.Packet {
	order := dhr.pktOpts[dhcp.OptionParameterRequestList]
	toAdd := []dhcp.Option{}
	var fileName, sName []byte
	// The DHCP spec implies that we should use the bootp sname and file
	// fields for options 66 and 67 unless the packet size grows large
	// enough that we should use them for storing DHCP options
	// instead. (RFC2132 sections 9.4 and 9.5), respectively. For now,
	// our DHCP packets are small enough that making that happen is not
	// a concern, so if we have 66 or 67 then fill in file and sname and
	// do not include those options directly.  Some day this logic should
	// become smarter.
	//
	// THis also appears to be required to make UEFI boot mode work properly on
	// the Dell T320.
	for _, opt := range dhr.outOpts.SelectOrderOrAll(order) {
		switch opt.Code {
		case dhcp.OptionBootFileName:
			fileName = opt.Value
		case dhcp.OptionTFTPServerName:
			sName = opt.Value
		default:
			toAdd = append(toAdd, opt)
		}
	}
	// Add renew and rebind times based on the expire time.
	if dhr.duration > 0 {
		toAdd = append(toAdd,
			dhcp.Option{
				Code:  dhcp.OptionRenewalTimeValue,
				Value: dhcp.OptionsLeaseTime(dhr.duration / 2),
			},
			dhcp.Option{
				Code:  dhcp.OptionRebindingTimeValue,
				Value: dhcp.OptionsLeaseTime(dhr.duration * 3 / 4),
			},
		)
	}
	res := dhcp.ReplyPacket(dhr.pkt, mt, serverID, yAddr, dhr.duration, toAdd)
	if dhr.nextServer.IsGlobalUnicast() {
		res.SetSIAddr(dhr.nextServer)
	}
	if fileName != nil {
		res.SetFile(fileName)
	}
	if sName != nil {
		res.SetSName(sName)
	}
	return res
}

// buildDhcpOptions builds the appropriate option set when we are the
// DHCP server of record for the incoming packet.  When we are, we do
// not include any PXE-specific DHCP options, as there are too many
// buggy NIC firmwares out there that don't quite implement the PXE
// spec appropriately.  They all appear to operate normally if you
// just throw file and sname fields at them, though.  Packets we are
// handling as a ProxyDHCP server or a straight up binl server do not
// use this method.
func (dhr *DhcpRequest) buildDhcpOptions(
	l *backend.Lease,
	s *backend.Subnet,
	r *backend.Reservation,
	serverID net.IP) {
	var leaseTime uint32 = 7200
	if s != nil {
		leaseTime = uint32(s.LeaseTimeFor(l.Addr) / time.Second)
	}
	dhr.nextServer = serverID
	dhr.duration = time.Duration(leaseTime) * time.Second
	dhr.coalesceOptions(l, s, r)
	if !dhr.offerPXE {
		delete(dhr.outOpts, dhcp.OptionTFTPServerName)
		delete(dhr.outOpts, dhcp.OptionBootFileName)
		delete(dhr.outOpts, dhcp.OptionVendorSpecificInformation)
		delete(dhr.outOpts, dhcp.OptionVendorClassIdentifier)
	}
}

func (dhr *DhcpRequest) Strategy(name string) StrategyFunc {
	for idx := range dhr.handler.strats {
		if dhr.handler.strats[idx].Name == name {
			return dhr.handler.strats[idx].GenToken
		}
	}
	return nil
}

// Helper for quickly generating a nak.
func (dhr *DhcpRequest) nak(addr net.IP) dhcp.Packet {
	return dhcp.ReplyPacket(dhr.pkt, dhcp.NAK, addr, nil, 0, nil)
}

const (
	reqInit = iota
	reqSelecting
	reqInitReboot
	reqRenewing
)

// Figure out what address is being requested (if any), and what sort
// of request it is.
func (dhr *DhcpRequest) reqAddr(msgType dhcp.MessageType) (addr net.IP, state int) {
	reqBytes, haveReq := dhr.pktOpts[dhcp.OptionRequestedIPAddress]
	if haveReq {
		addr = net.IP(reqBytes)
	} else {
		addr = dhr.pkt.CIAddr()
	}
	_, haveSI := dhr.pktOpts[dhcp.OptionServerIdentifier]
	state = reqInit
	switch msgType {
	case dhcp.Request:
		if haveSI {
			state = reqSelecting
		} else if haveReq {
			state = reqInitReboot
		} else {
			state = reqRenewing
		}
	}
	return
}

// FakeLease is a helper function for fetching a fake lease from the
// backend.  We use fake leases when handling ProxyDHCP and binl
// requests, as we don't actually want to allocate an IP address or
// anything crazy like that.
func (dhr *DhcpRequest) FakeLease(req net.IP) (*backend.Lease, *backend.Subnet, *backend.Reservation) {
	rt := dhr.Request("leases", "reservations", "subnets")
	for _, s := range dhr.handler.strats {
		strat := s.Name
		token := s.GenToken(dhr.pkt, dhr.pktOpts)
		via := []net.IP{dhr.pkt.GIAddr()}
		if via[0] == nil || via[0].IsUnspecified() {
			via = dhr.listenIPs()
		}
		lease, sub, res := backend.FakeLeaseFor(rt, strat, token, via)
		if sub == nil && res == nil {
			continue
		}
		if lease != nil {
			lease.Addr = req
		}
		return lease, sub, res
	}
	return nil, nil, nil
}

// buildBinlOptions builds appropriate DHCP options for use in
// ProxyDHCP and binl handling.  These responses only include PXE
// specific options.
func (dhr *DhcpRequest) buildBinlOptions(
	l *backend.Lease,
	s *backend.Subnet,
	r *backend.Reservation,
	serverID net.IP) {
	dhr.nextServer = serverID
	dhr.coalesceOptions(l, s, r)
	if !dhr.offerPXE {
		return
	}
	opts := dhcp.Options{dhcp.OptionVendorClassIdentifier: []byte("PXEClient")}
	if arch, ok := dhr.pktOpts[dhcp.OptionClientArchitecture]; ok {
		opt := &models.DhcpOption{Code: byte(dhcp.OptionClientArchitecture)}
		opt.FillFromPacketOpt(arch)
		// Hack to work around buggy old UEFI firmware.
		if opt.Value == "0" {
			// PXE options are as follows:
			// Discovery control: autoboot with provided name.
			pxeOpts := []byte{0x06, 0x01, 0x08, 0xff}
			opts[dhcp.OptionVendorSpecificInformation] = pxeOpts
		}
	}
	// Send back the GUID if we got a guid
	if dhr.pktOpts[97] != nil {
		opts[97] = dhr.pktOpts[97]
	}
	opts[dhcp.OptionBootFileName] = dhr.outOpts[dhcp.OptionBootFileName]
	opts[dhcp.OptionTFTPServerName] = dhr.outOpts[dhcp.OptionTFTPServerName]
	dhr.outOpts = opts
}

// ServeBinl is responsible for handling ProxyDHCP Request messages
// and binl Discover messages.  Both of those come in on port 4011.
func (dhr *DhcpRequest) ServeBinl(msgType dhcp.MessageType) (dhcp.Packet, string) {
	req, _ := dhr.reqAddr(msgType)
	if !(msgType == dhcp.Discover || msgType == dhcp.Request) {
		dhr.Infof("%s: Ignoring DHCP %s from %s to the BINL service", dhr.xid(), msgType, req)
	}
	// By default, all responses will be ACKs
	respType := dhcp.ACK
	if msgType == dhcp.Request && !req.IsGlobalUnicast() {
		dhr.Infof("%s: NAK'ing invalid requested IP %s", dhr.xid(), req)
		return dhr.nak(dhr.respondFrom(req)), "NAK"
	}
	lease, subnet, reservation := dhr.FakeLease(req)
	if lease == nil {
		return nil, "NoInfo"
	}
	lease.Addr = req
	serverID := dhr.respondFrom(req)
	dhr.buildBinlOptions(lease, subnet, reservation, serverID)
	if !dhr.offerPXE {
		dhr.Infof("%s: BINL directed to not offer PXE response to %s", dhr.xid(), req)
		return nil, "NoPXE"
	}
	reply := dhr.buildReply(respType, serverID, req)
	return reply, "ACK"
}

// ServeDHCP is responsible for handling regular DHCP traffic as well
// as ProxyDHCP DISCOVER messages -- essentially everything that comes
// in on port 67.
func (dhr *DhcpRequest) ServeDHCP(msgType dhcp.MessageType) (dhcp.Packet, string) {
	// need code to figure out which interface or relay it came from
	req, reqState := dhr.reqAddr(msgType)
	var err error
	switch msgType {
	case dhcp.Offer:
		serverBytes, ok := dhr.pktOpts[dhcp.OptionServerIdentifier]
		server := net.IP(serverBytes)
		if ok && !dhr.isOneOfMyAddrs(server) {
			dhr.Warnf("WARNING: %s: Competing DHCP server on network: %s", dhr.xid(), server)
		}
		if !dhr.isOneOfMyAddrs(dhr.cm.Src) {
			dhr.Warnf("WARNING: %s: Competing DHCP server on network: %s", dhr.xid(), dhr.cm.Src)
		}
	case dhcp.Decline:
		rt := dhr.Request("leases")
		rt.Do(func(d backend.Stores) {
			leaseThing := rt.Find("leases", models.Hexaddr(req))
			if leaseThing == nil {
				rt.Infof("%s: Asked to decline a lease we didn't issue by %s, ignoring", dhr.xid(), req)
				return
			}
			lease := backend.AsLease(leaseThing)
			stratfn := dhr.Strategy(lease.Strategy)
			if stratfn != nil && stratfn(dhr.pkt, dhr.pktOpts) == lease.Token {
				dhr.Infof("%s: Lease for %s declined, invalidating.", dhr.xid(), lease.Addr)
				lease.Invalidate()
				rt.Save(lease)
			} else {
				dhr.Infof("%s: Received spoofed decline for %s, ignoring", dhr.xid(), lease.Addr)
			}
		})
	case dhcp.Release:
		rt := dhr.Request("leases")
		rt.Do(func(d backend.Stores) {
			leaseThing := rt.Find("leases", models.Hexaddr(req))
			if leaseThing == nil {
				rt.Infof("%s: Asked to release a lease we didn't issue by %s, ignoring", dhr.xid(), req)
				return
			}
			lease := backend.AsLease(leaseThing)
			stratfn := dhr.Strategy(lease.Strategy)
			if stratfn != nil && stratfn(dhr.pkt, dhr.pktOpts) == lease.Token {
				rt.Infof("%s: Lease for %s released, expiring.", dhr.xid(), lease.Addr)
				lease.Expire()
				rt.Save(lease)
			} else {
				rt.Infof("%s: Received spoofed release for %s, ignoring", dhr.xid(), lease.Addr)
			}
		})
	case dhcp.Request:
		serverBytes, ok := dhr.pktOpts[dhcp.OptionServerIdentifier]
		server := net.IP(serverBytes)
		if ok && !dhr.listenOn(server) {
			dhr.Warnf("%s: Ignoring request for DHCP server %s", dhr.xid(), net.IP(server))
			return nil, "OtherServer"
		}
		if !req.IsGlobalUnicast() {
			dhr.Infof("%s: NAK'ing invalid requested IP %s", dhr.xid(), req)
			return dhr.nak(dhr.respondFrom(req)), "NAK"
		}
		var lease *backend.Lease
		var reservation *backend.Reservation
		var subnet *backend.Subnet
		rt := dhr.Request("leases", "reservations", "subnets")
		for _, s := range dhr.handler.strats {
			lease, subnet, reservation, err = backend.FindLease(rt, s.Name, s.GenToken(dhr.pkt, dhr.pktOpts), req)
			if lease == nil &&
				subnet == nil &&
				reservation == nil &&
				err == nil {
				continue
			}
			if err != nil {
				if lease != nil {
					dhr.Infof("%s: %s already leased to %s:%s: %s",
						dhr.xid(),
						req,
						lease.Strategy,
						lease.Token,
						err)
				} else {
					dhr.Warnf("%s: Another DHCP server may be on the network: %s", dhr.xid(), net.IP(server))
					dhr.Infof("%s: %s is no longer able to be leased: %s",
						dhr.xid(),
						req,
						err)
				}
				return dhr.nak(dhr.respondFrom(req)), "NAK"
			}
			if lease != nil {
				break
			}
		}
		if lease == nil {
			if reqState == reqInitReboot {
				dhr.Infof("%s: No lease for %s in database, client in INIT-REBOOT.  Ignoring request.", dhr.xid(), req)
				return nil, "NoLease"
			}
			if subnet != nil || reservation != nil {
				dhr.Infof("%s: No lease for %s in database, NAK'ing", dhr.xid(), req)
				return dhr.nak(dhr.respondFrom(req)), "NAK"
			}

			dhr.Infof("%s: No lease in database, and no subnet or reservation covers %s. Ignoring request", dhr.xid(), req)
			return nil, "NoLease"
		}
		if lease.Fake() {
			dhr.Infof("%s: Proxy Subnet should not respond to %s.", dhr.xid(), req)
			return nil, "ProxySubnet"
		}
		serverID := dhr.respondFrom(lease.Addr)
		dhr.buildDhcpOptions(lease, subnet, reservation, serverID)
		reply := dhr.buildReply(dhcp.ACK, serverID, lease.Addr)
		rt.Infof("%s: Request handing out: %s to %s via %s",
			dhr.xid(),
			reply.YIAddr(),
			reply.CHAddr(),
			serverID)
		return reply, "ACK"
	case dhcp.Discover:
		for _, s := range dhr.handler.strats {
			strat := s.Name
			token := s.GenToken(dhr.pkt, dhr.pktOpts)
			via := []net.IP{dhr.pkt.GIAddr()}
			if via[0] == nil || via[0].IsUnspecified() {
				via = dhr.listenIPs()
			}
			var (
				lease       *backend.Lease
				subnet      *backend.Subnet
				reservation *backend.Reservation
			)
			rt := dhr.Request("leases", "reservations", "subnets")
			for {
				var fresh bool
				lease, subnet, reservation, fresh = backend.FindOrCreateLease(rt, strat, token, req, via)
				if lease == nil {
					break
				}
				switch lease.State {
				case "FAKE":
					rt.Debugf("%s: Proxy subnet, using fake lease", dhr.xid())
				case "PROBE":
					if !fresh {
						// Someone other goroutine is already working this lease.
						rt.Debugf("%s: Ignoring DISCOVER from %s, its request is being processed by another goroutine", dhr.xid(), token)
						return nil, "InFlight"
					}
					rt.Debugf("%s: Testing to see if %s is in use", dhr.xid(), lease.Addr)
					addrUsed, valid := <-dhr.pinger.InUse(lease.Addr.String(), 3*time.Second)
					if !valid {
						rt.Do(func(d backend.Stores) {
							rt.Debugf("%s: System shutting down, deleting lease for %s", dhr.xid(), lease.Addr)
							rt.Remove(lease)
						})
						return nil, "Leaving"
					}
					if addrUsed {
						rt.Do(func(d backend.Stores) {
							rt.Debugf("%s: IP address %s in use by something else, marking it as unusable for an hour.", dhr.xid(), lease.Addr)
							lease.Invalidate()
							rt.Save(lease)
						})
						continue
					}
					rt.Do(func(d backend.Stores) {
						rt.Debugf("%s: IP address %s appears to be free", dhr.xid(), lease.Addr)
						lease.State = "Offer"
						rt.Save(lease)
					})
				default:
					rt.Debugf("%s: Reusing lease for %s", dhr.xid(), lease.Addr)
				}
				break
			}
			if lease == nil {
				return nil, "NoLease"
			}
			if lease.Fake() {
				lease.Addr = net.IPv4(0, 0, 0, 0)
				serverID := dhr.respondFrom(lease.Addr)
				// This is a proxy DHCP response
				dhr.buildBinlOptions(lease, subnet, reservation, serverID)
				if !dhr.offerPXE {
					return nil, "NoPXE"
				}
				reply := dhr.buildReply(dhcp.Offer, serverID, lease.Addr)
				reply.SetBroadcast(true)

				dhr.Infof("%s: Sending ProxyDHCP offer to %s via %s", dhr.xid(), reply.CHAddr(), serverID)
				return reply, "Offer"
			}
			serverID := dhr.respondFrom(lease.Addr)
			dhr.buildDhcpOptions(lease, subnet, reservation, serverID)
			reply := dhr.buildReply(dhcp.Offer, serverID, lease.Addr)
			// Say who we are.
			dhr.Infof("%s: Discovery handing out: %s to %s via %s",
				dhr.xid(),
				reply.YIAddr(),
				reply.CHAddr(),
				serverID)
			return reply, "Offer"
		}
	}
	return nil, "NotHandled"
}

// Process is responsible for checking basic sanity of an incoming
// DHCP packet, handing it off to ServeDHCP or ServeBinl, and
// performing some common post-processing if we have an outgoing
// packet to send.
func (dhr *DhcpRequest) Process() (dhcp.Packet, string, string) {
	if dhr.IsDebug() {
		dhr.Debugf("Handling packet:\n%s", dhr.PrintIncoming())
	}
	if dhr.pkt.HLen() > 16 {
		dhr.Errorf("Invalid hlen")
		return nil, "InvalidHlen", "Error"
	}
	dhr.pktOpts = dhr.pkt.ParseOptions()
	var reqType dhcp.MessageType
	if t, ok := dhr.pktOpts[dhcp.OptionDHCPMessageType]; !ok || len(t) != 1 {
		dhr.Errorf("Missing DHCP message type")
		return nil, "MissingType", "Error"
	} else if reqType = dhcp.MessageType(t[0]); reqType < dhcp.Discover || reqType > dhcp.Inform {
		dhr.Errorf("Invalid DHCP message type")
		return nil, "InvalidType", "Error"
	}
	tgtName := dhr.ifname()
	if tgtName == "" {
		dhr.Infof("Inferface at index %d vanished", dhr.cm.IfIndex)
		return nil, reqType.String(), "BadInterface"
	}
	if len(dhr.handler.ifs) > 0 {
		canProcess := false
		for _, ifName := range dhr.handler.ifs {
			if strings.TrimSpace(ifName) == tgtName {
				canProcess = true
				break
			}
		}
		if !canProcess {
			dhr.Infof("%s Ignoring packet from interface %s", dhr.xid(), tgtName)
			return nil, reqType.String(), "Ignored"
		}
	}
	var res dhcp.Packet
	var resType string
	if dhr.binlOnly() {
		res, resType = dhr.ServeBinl(reqType)
	} else {
		res, resType = dhr.ServeDHCP(reqType)
	}
	if res == nil {
		return nil, reqType.String(), resType
	}
	// If IP not available, broadcast
	ipStr, portStr, err := net.SplitHostPort(dhr.srcAddr.String())
	if err != nil {
		return nil, reqType.String(), "BadBcast"
	}
	port, _ := strconv.Atoi(portStr)
	if dhr.pkt.GIAddr().Equal(net.IPv4zero) {
		if net.ParseIP(ipStr).Equal(net.IPv4zero) || dhr.pkt.Broadcast() {
			dhr.srcAddr = &net.UDPAddr{IP: net.IPv4bcast, Port: port}
		}
	} else {
		dhr.srcAddr = &net.UDPAddr{IP: dhr.pkt.GIAddr(), Port: port}
	}
	dhr.cm.Src = nil
	if dhr.IsDebug() {
		dhr.Debugf("Sending packet:\n%s", dhr.PrintOutgoing(res))
	}
	return res, reqType.String(), resType
}

// Run processes an incoming DhcpRequest and sends the resulting
// packet (if any) back out over the same interface it came in on.
func (dhr *DhcpRequest) Run(count int) {
	res, rqt, rst := dhr.Process()
	if res != nil {
		dhr.handler.conn.WriteTo(res, dhr.cm, dhr.srcAddr)
	}

	elapsed := float64(time.Since(dhr.start)) / float64(time.Second)
	dhr.handler.metrics.CountPacket(float64(count), elapsed, res, rqt, rst)
}

// DhcpHandler is responsible for listening to incoming DHCP packets,
// building a DhcpRequest for each one, then kicking that reqest off
// to handle the packet.
type DhcpHandler struct {
	logger.Logger
	waitGroup  *sync.WaitGroup
	closing    bool
	binlOnly   bool
	ifs        []string
	port       int
	conn       *ipv4.PacketConn
	bk         *backend.DataTracker
	pinger     pinger.Pinger
	strats     []*Strategy
	publishers *backend.Publishers
	metrics    *DhcpMetrics
}

func (h *DhcpHandler) NewRequest(buf []byte, cm *ipv4.ControlMessage, srcAddr net.Addr, start time.Time) *DhcpRequest {
	res := &DhcpRequest{}
	res.Logger = h.Logger.Fork()
	res.srcAddr = srcAddr
	res.defaultIP = net.ParseIP(h.bk.OurAddress)
	res.cm = cm
	res.pkt = dhcp.Packet(buf)
	res.handler = h
	res.pinger = h.pinger
	res.lPort = h.port
	res.start = start
	res.fill()
	return res
}

func (h *DhcpHandler) Serve() error {
	defer h.waitGroup.Done()
	defer h.conn.Close()
	buf := make([]byte, 16384) // account for non-Ethernet devices maybe being used.
	for {
		h.conn.SetReadDeadline(time.Now().Add(time.Second))
		cnt, cm, srcAddr, err := h.conn.ReadFrom(buf)
		if err, ok := err.(net.Error); ok && err.Timeout() {
			continue
		}
		if err != nil {
			return err
		}
		start := time.Now()
		if cnt < 240 {
			h.metrics.CountPacket(float64(cnt), float64(0), nil, "TooSmall", "TooSmall")
			continue
		}
		pktBytes := make([]byte, cnt)
		copy(pktBytes, buf)
		go h.NewRequest(pktBytes, cm, srcAddr, start).Run(cnt)
	}
}

func (h *DhcpHandler) Shutdown(ctx context.Context) error {
	h.Infof("Shutting down DHCP handler")
	h.closing = true
	h.conn.Close()
	if h.pinger != nil {
		h.pinger.Close()
	}
	h.waitGroup.Wait()
	h.Infof("DHCP handler shut down")
	return nil
}

type Service interface {
	Shutdown(context.Context) error
}

func StartDhcpHandler(dhcpInfo *backend.DataTracker,
	log logger.Logger,
	dhcpIfs string,
	dhcpPort int,
	pubs *backend.Publishers,
	proxyOnly bool,
	fakePinger bool) (Service, error) {

	ifs := []string{}
	if dhcpIfs != "" {
		ifs = strings.Split(dhcpIfs, ",")
	}
	handler := &DhcpHandler{
		Logger:     log,
		waitGroup:  &sync.WaitGroup{},
		ifs:        ifs,
		bk:         dhcpInfo,
		port:       dhcpPort,
		strats:     []*Strategy{{Name: "MAC", GenToken: MacStrategy}},
		publishers: pubs,
		binlOnly:   proxyOnly,
		metrics:    NewDhcpMetrics(log, proxyOnly),
	}

	// If we aren't the PXE/BINL proxy, run a pinger
	if !proxyOnly {
		if handler.pinger == nil {
			if fakePinger {
				handler.pinger = pinger.Fake(true)
			} else {
				pinger, err := pinger.ICMP()
				if err != nil {
					return nil, err
				}
				handler.pinger = pinger
			}
		}
		rt := handler.bk.Request(log, "leases")
		rt.Do(func(d backend.Stores) {
			for _, leaseThing := range d("leases").Items() {
				lease := backend.AsLease(leaseThing)
				if lease.State != "PROBE" {
					continue
				}
				rt.Remove(lease)
			}
		})
	}

	l, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", handler.port))
	if err != nil {
		return nil, err
	}
	handler.conn = ipv4.NewPacketConn(l)
	if err := handler.conn.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		l.Close()
		return nil, err
	}
	handler.waitGroup.Add(1)
	go func() {
		err := handler.Serve()
		if !handler.closing {
			handler.Fatalf("DHCP(%v) handler died: %v", proxyOnly, err)
		}
	}()
	return handler, nil
}
