package midlayer

import (
	"net"
	"strings"

	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/models"
	dhcp "github.com/krolaw/dhcp4"
)

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
		if !opts.comboot {
			dhr.Warnf("Incoming iPXE does not support comboot")
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

func btouint16(b []byte) uint16 {
	return uint16(b[0])<<8 + uint16(b[1])
}

func btouint32(b []byte) uint32 {
	return uint32(b[0])<<24 + uint32(b[1])<<16 + uint32(b[2])<<8 + uint32(b[3])
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

func (dhr *DhcpRequest) offerPXE() bool {
	if val, ok := dhr.pktOpts[dhcp.OptionVendorClassIdentifier]; ok &&
		strings.HasPrefix(string(val), "PXEClient") {
		return true
	}
	return false
}

// fillForPXE is responsible for determining whether we should handle
// this options as a PXE request, and adding any required out options
// based
func (dhr *DhcpRequest) fillForPXE(l *backend.Lease) {
	// The reservation already populated a BootFileName, use it.
	if _, ok := dhr.outOpts[dhcp.OptionBootFileName]; ok {
		return
	}
	// No BootFileName, fill out some sane defaults
	fname := ""
	var arch uint
	if val, ok := dhr.pktOpts[dhcp.OptionClientArchitecture]; ok {
		arch = uint(val[0])<<8 + uint(val[1])
	}
	inIPxe := false
	if val, ok := dhr.pktOpts[dhcp.OptionUserClass]; ok &&
		string(val) == "iPXE" {
		inIPxe = true
	}
	if inIPxe && dhr.ipxeIsSane(arch) {
		fname = "default.ipxe"
	} else {
		switch arch {
		case 0:
			if inIPxe {
				fname = "ipxe.pxe"
			} else {
				fname = "lpxelinux.0"
			}
		case 7, 9:
			fname = "ipxe.efi"
		case 6:
			dhr.Errorf("dr-provision does not support 32 bit EFI systems")
		case 10:
			dhr.Errorf("dr-provision does not support 32 bit ARM EFI systems")
		case 11:
			fname = "ipxe-arm64.efi"
		default:
			dhr.Errorf("Unknown client arch %d: cannot PXE boot it remotely", arch)
		}
	}
	if fname == "" {
		dhr.offerNetBoot = false
		return
	}
	dhr.outOpts[dhcp.OptionBootFileName] = []byte(fname)
}

// buildBinlOptions builds appropriate DHCP options for use in
// ProxyDHCP and binl handling.  These responses only include PXE
// specific options.
func (dhr *DhcpRequest) buildBinlOptions(l *backend.Lease, serverID net.IP) {
	dhr.nextServer = serverID
	dhr.coalesceOptions(l)
	if !dhr.offerNetBoot {
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
func (dhr *DhcpRequest) ServeBinl() string {
	req, _ := dhr.reqAddr(dhr.reqType)
	if !(dhr.reqType == dhcp.Discover || dhr.reqType == dhcp.Request) {
		dhr.Infof("%s: Ignoring DHCP %s from %s to the BINL service", dhr.xid(), dhr.reqType, req)
	}
	// By default, all responses will be ACKs
	respType := dhcp.ACK
	if dhr.reqType == dhcp.Request && !req.IsGlobalUnicast() {
		dhr.Infof("%s: NAK'ing invalid requested IP %s", dhr.xid(), req)
		dhr.nak(dhr.respondFrom(req))
		return "NAK"
	}
	lease := dhr.FakeLease(req)
	if lease == nil {
		return "NoInfo"
	}
	lease.Addr = req
	serverID := dhr.respondFrom(req)
	dhr.buildBinlOptions(lease, serverID)
	if !dhr.offerNetBoot {
		dhr.Infof("%s: BINL directed to not offer PXE response to %s", dhr.xid(), req)
		return "NoPXE"
	}
	dhr.Reply(dhr.buildReply(respType, serverID, req))
	return "ACK"
}
