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
	idxMap                        map[int][]*net.IPNet
	nameMap                       map[int]string
	srcAddr                       net.Addr
	defaultIP, nextServer         net.IP
	cm                            *ipv4.ControlMessage
	request                       dhcp.Packet
	replies                       []dhcp.Packet
	pktOpts, outOpts, netBootOpts dhcp.Options
	pinger                        pinger.Pinger
	handler                       *DhcpHandler
	lPort                         int
	reqType                       dhcp.MessageType
	offerNetBoot                  bool
	duration                      time.Duration
	start                         time.Time
	machine                       *backend.Machine
	bootEnv                       *backend.BootEnv
}

func (dhr *DhcpRequest) Reply(p dhcp.Packet) {
	dhr.replies = append(dhr.replies, p)
}

// xid is a helper function that returns the xid of the request we are
// working on in a format suitable for inclusion in a log message.
func (dhr *DhcpRequest) xid() string {
	return fmt.Sprintf("xid 0x%x", binary.BigEndian.Uint32(dhr.request.XId()))
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

func (dhr *DhcpRequest) checkMachine(l *backend.Lease, s *backend.Subnet) {
	// If the incoming packet does not want a filename, it does not want
	// to net boot.
	if vals, ok := dhr.pktOpts[dhcp.OptionParameterRequestList]; !ok ||
		bytes.IndexByte(vals, byte(dhcp.OptionBootFileName)) == -1 {
		dhr.offerNetBoot = false
		return
	}
	// If we have a dhcp.OptionBootFileName set to "", a reservation told us
	// to not net boot.
	if val, ok := dhr.outOpts[dhcp.OptionBootFileName]; ok && len(val) == 0 {
		dhr.offerNetBoot = false
		return
	}
	// If the subnet is unmanaged, we never want machines to PXE boot from it.
	if s != nil && s.Unmanaged {
		dhr.offerNetBoot = false
		return
	}
	rt := dhr.Request(dhr.machine.Locks("update")...)
	rt.Do(func(d backend.Stores) {
		dhr.machine = rt.MachineForMac(dhr.request.CHAddr().String())
		if dhr.machine == nil {
			m2 := rt.FindByIndex("machines", dhr.machine.Indexes()["Address"], l.Addr.String())
			if m2 != nil {
				dhr.machine = backend.AsMachine(m2)
			}
		}
		if dhr.machine == nil {
			// No machine known for this MAC address or IP address.  It can
			// PXE boot if it wants.
			dhr.offerNetBoot = true
			return
		}
		if bk := rt.Find("bootenvs", dhr.machine.BootEnv); bk != nil {
			dhr.bootEnv = backend.AsBootEnv(bk)
		} else {
			// This should never happen, but if it does then Something Bad
			// happened, and we will allow it to PXE boot if it wants.
			rt.Errorf("%s: Machine %s refers to missing BootEnv %s",
				dhr.xid(),
				dhr.machine.UUID(),
				dhr.machine.BootEnv)
			dhr.offerNetBoot = true
			return
		}
		if !dhr.bootEnv.NetBoot() {
			// We found a machine, and the bootenv it is set to does not
			// want to net boot.  We should not let it PXE boot from us.
			dhr.offerNetBoot = false
			return
		}
		if l.Addr.IsUnspecified() {
			// We do not have a valid lease for this mac address.
			// DO not let it boot.
			dhr.offerNetBoot = false
			return
		}
		dhr.offerNetBoot = true
		if l.Fake() {
			return
		}
		// We want the machine to PXE boot, and we know what address it is
		// getting.  However, that address may not be one that we are
		// currently rendering templates for.  Check to see if we need to
		// update the machine's address of record.
		machineSave := !dhr.machine.Address.Equal(l.Addr)
		others, err := index.All(
			index.Sort(dhr.machine.Indexes()["Address"]),
			index.Eq(l.Addr.String()))(rt.Index("machines"))
		if err == nil && others.Count() > 0 {
			for _, other := range others.Items() {
				if other.Key() == dhr.machine.UUID() {
					continue
				}
				oMachine := backend.AsMachine(other)
				rt.Warnf("Machine %s also has address %s, which we are handing out to %s", oMachine.UUID(), l.Addr, dhr.machine.UUID())
				rt.Warnf("Setting machine %s address to all zeros", oMachine.UUID())
				oMachine.Address = net.IPv4(0, 0, 0, 0)
				rt.Save(oMachine)
			}
		}
		if machineSave {
			rt.Warnf("%s: Updating machine %s address from %s to %s", dhr.xid(), dhr.machine.UUID(), dhr.machine.Address, l.Addr)
			dhr.machine.Address = l.Addr
			rt.Save(dhr.machine)
		}
	})
}

// coalesceOptions is responsible for building the options we will
// reply with, as well as figuring out whether or not we should offer
// PXE and TFTP file name options in the outgoing packet.
func (dhr *DhcpRequest) coalesceOptions(
	l *backend.Lease,
	s *backend.Subnet,
	r *backend.Reservation) {
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
	dhr.checkMachine(l, s)
	if dhr.offerNetBoot && dhr.offerPXE() {
		dhr.fillForPXE(l, s)
		return
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
	if !dhr.offerNetBoot {
		delete(dhr.outOpts, dhcp.OptionTFTPServerName)
		delete(dhr.outOpts, dhcp.OptionBootFileName)
		delete(dhr.outOpts, dhcp.OptionVendorSpecificInformation)
		delete(dhr.outOpts, dhcp.OptionVendorClassIdentifier)
		delete(dhr.outOpts, dhcp.OptionRootPath)
	}
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
	res := dhcp.ReplyPacket(dhr.request, mt, serverID, yAddr, dhr.duration, toAdd)
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
func (dhr *DhcpRequest) nak(addr net.IP) {
	dhr.Reply(dhcp.ReplyPacket(dhr.request, dhcp.NAK, addr, nil, 0, nil))
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
		addr = dhr.request.CIAddr()
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
		strategy := s.Name
		token := s.GenToken(dhr.request, dhr.pktOpts)
		via := []net.IP{dhr.request.GIAddr()}
		if via[0] == nil || via[0].IsUnspecified() {
			via = dhr.listenIPs()
		}
		lease, sub, res := backend.FakeLeaseFor(rt, strategy, token, via)
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

// ServeDHCP is responsible for handling regular DHCP traffic as well
// as ProxyDHCP DISCOVER messages -- essentially everything that comes
// in on port 67.
func (dhr *DhcpRequest) ServeDHCP() string {
	// need code to figure out which interface or relay it came from
	req, reqState := dhr.reqAddr(dhr.reqType)
	var err error
	switch dhr.reqType {
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
			if stratfn != nil && stratfn(dhr.request, dhr.pktOpts) == lease.Token {
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
			if stratfn != nil && stratfn(dhr.request, dhr.pktOpts) == lease.Token {
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
			return "OtherServer"
		}
		if !req.IsGlobalUnicast() {
			dhr.Infof("%s: NAK'ing invalid requested IP %s", dhr.xid(), req)
			dhr.nak(dhr.respondFrom(req))
			return "NAK"
		}
		var lease *backend.Lease
		var reservation *backend.Reservation
		var subnet *backend.Subnet
		rt := dhr.Request("leases", "reservations", "subnets")
		for _, s := range dhr.handler.strats {
			lease, subnet, reservation, err = backend.FindLease(rt, s.Name, s.GenToken(dhr.request, dhr.pktOpts), req)
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
				dhr.nak(dhr.respondFrom(req))
				return "NAK"
			}
			if lease != nil {
				break
			}
		}
		if lease == nil {
			if reqState == reqInitReboot {
				dhr.Infof("%s: No lease for %s in database, client in INIT-REBOOT.  Ignoring request.", dhr.xid(), req)
				return "NoLease"
			}
			if subnet != nil || reservation != nil {
				dhr.Infof("%s: No lease for %s in database, NAK'ing", dhr.xid(), req)
				dhr.nak(dhr.respondFrom(req))
				return "NAK"
			}

			dhr.Infof("%s: No lease in database, and no subnet or reservation covers %s. Ignoring request", dhr.xid(), req)
			return "NoLease"
		}
		if lease.Fake() {
			dhr.Infof("%s: Proxy Subnet should not respond to %s.", dhr.xid(), req)
			return "ProxySubnet"
		}
		serverID := dhr.respondFrom(lease.Addr)
		dhr.buildDhcpOptions(lease, subnet, reservation, serverID)
		reply := dhr.buildReply(dhcp.ACK, serverID, lease.Addr)
		rt.Infof("%s: Request handing out: %s to %s via %s",
			dhr.xid(),
			reply.YIAddr(),
			reply.CHAddr(),
			serverID)
		dhr.Reply(reply)
		return "ACK"
	case dhcp.Discover:
		for _, s := range dhr.handler.strats {
			strategy := s.Name
			token := s.GenToken(dhr.request, dhr.pktOpts)
			via := []net.IP{dhr.request.GIAddr()}
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
				lease, subnet, reservation, fresh = backend.FindOrCreateLease(rt, strategy, token, req, via)
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
						return "InFlight"
					}
					rt.Debugf("%s: Testing to see if %s is in use", dhr.xid(), lease.Addr)
					addrUsed, valid := <-dhr.pinger.InUse(lease.Addr.String(), 3*time.Second)
					if !valid {
						rt.Do(func(d backend.Stores) {
							rt.Debugf("%s: System shutting down, deleting lease for %s", dhr.xid(), lease.Addr)
							rt.Remove(lease)
						})
						return "Leaving"
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
				return "NoLease"
			}
			if lease.Fake() {
				lease.Addr = net.IPv4(0, 0, 0, 0)
				serverID := dhr.respondFrom(lease.Addr)
				// This is a proxy DHCP response
				dhr.buildBinlOptions(lease, subnet, reservation, serverID)
				if !dhr.offerNetBoot {
					return "NoPXE"
				}
				reply := dhr.buildReply(dhcp.Offer, serverID, lease.Addr)
				reply.SetBroadcast(true)

				dhr.Infof("%s: Sending ProxyDHCP offer to %s via %s", dhr.xid(), reply.CHAddr(), serverID)
				dhr.Reply(reply)
				return "Offer"
			}
			serverID := dhr.respondFrom(lease.Addr)
			dhr.buildDhcpOptions(lease, subnet, reservation, serverID)
			if dhr.offerAppleBoot() {
				// Apple's net boot protocol requires that we send a second Offer packet.
				dhr.offerNetBoot = false
			}
			reply := dhr.buildReply(dhcp.Offer, serverID, lease.Addr)
			// Say who we are.
			dhr.Infof("%s: Discovery handing out: %s to %s via %s",
				dhr.xid(),
				reply.YIAddr(),
				reply.CHAddr(),
				serverID)
			dhr.Reply(reply)
			if dhr.offerAppleBoot() {
				dhr.offerNetBoot = true
				dhr.buildAppleBsdpOptions(serverID)
				dhr.Reply(dhr.buildReply(dhcp.Offer, serverID, net.IPv4zero))
			}
			return "Offer"
		}
	}
	return "NotHandled"
}

// Process is responsible for checking basic sanity of an incoming
// DHCP packet, handing it off to ServeDHCP or ServeBinl, and
// performing some common post-processing if we have an outgoing
// packet to send.
func (dhr *DhcpRequest) Process() (string, string) {
	if dhr.IsDebug() {
		dhr.Debugf("Handling packet:\n%s", dhr.PrintIncoming())
	}
	if dhr.request.HLen() > 16 {
		dhr.Errorf("Invalid hlen")
		return "InvalidHlen", "Error"
	}
	dhr.pktOpts = dhr.request.ParseOptions()
	if t, ok := dhr.pktOpts[dhcp.OptionDHCPMessageType]; !ok || len(t) != 1 {
		dhr.Errorf("Missing DHCP message type")
		return "MissingType", "Error"
	} else if dhr.reqType = dhcp.MessageType(t[0]); dhr.reqType < dhcp.Discover || dhr.reqType > dhcp.Inform {
		dhr.Errorf("Invalid DHCP message type")
		return "InvalidType", "Error"
	}
	tgtName := dhr.ifname()
	if tgtName == "" {
		dhr.Infof("Inferface at index %d vanished", dhr.cm.IfIndex)
		return dhr.reqType.String(), "BadInterface"
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
			return dhr.reqType.String(), "Ignored"
		}
	}
	var resType string
	if dhr.binlOnly() {
		resType = dhr.ServeBinl()
	} else if dhr.reqType == dhcp.Inform && dhr.offerAppleBoot() {
		resType = dhr.ServeAppleBSDP()
	} else {
		resType = dhr.ServeDHCP()
	}
	if len(dhr.replies) == 0 {
		return dhr.reqType.String(), resType
	}
	// If IP not available, broadcast
	ipStr, portStr, err := net.SplitHostPort(dhr.srcAddr.String())
	if err != nil {
		return dhr.reqType.String(), "BadBcast"
	}
	port, _ := strconv.Atoi(portStr)
	if dhr.request.GIAddr().Equal(net.IPv4zero) {
		if net.ParseIP(ipStr).Equal(net.IPv4zero) || dhr.request.Broadcast() {
			dhr.srcAddr = &net.UDPAddr{IP: net.IPv4bcast, Port: port}
		}
	} else {
		dhr.srcAddr = &net.UDPAddr{IP: dhr.request.GIAddr(), Port: port}
	}
	dhr.cm.Src = nil
	return dhr.reqType.String(), resType
}

// Run processes an incoming DhcpRequest and sends the resulting
// packet (if any) back out over the same interface it came in on.
func (dhr *DhcpRequest) Run(count int) {
	rqt, rst := dhr.Process()
	if len(dhr.replies) > 0 {
		for i := range dhr.replies {
			if dhr.IsDebug() {
				dhr.Debugf("Sending packet:\n%s", dhr.PrintOutgoing(dhr.replies[i]))
			}
			dhr.handler.conn.WriteTo(dhr.replies[i], dhr.cm, dhr.srcAddr)
			elapsed := float64(time.Since(dhr.start)) / float64(time.Second)
			dhr.handler.metrics.CountPacket(float64(count), elapsed, dhr.replies[i], rqt, rst)
		}
	} else {
		elapsed := float64(time.Since(dhr.start)) / float64(time.Second)
		dhr.handler.metrics.CountPacket(float64(count), elapsed, nil, rqt, rst)
	}
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
	res.request = dhcp.Packet(buf)
	res.replies = []dhcp.Packet{}
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
