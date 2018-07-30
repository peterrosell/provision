package midlayer

import (
	"bytes"
	"fmt"
	"net"
	"path"
	"strings"

	"github.com/digitalrebar/provision/models"
	dhcp "github.com/krolaw/dhcp4"
)

const (
	bsdpList   = 1
	bsdpSelect = 2
	bsdpFail   = 3
)

type bsdpBootOption models.BsdpBootOption

func (bo *bsdpBootOption) FromOption(buf []byte) {
	bo.Install = buf[0]&0x80 > 0
	bo.OSType = buf[0] | 0x7f
	bo.Index = uint16(buf[2])<<8 + uint16(buf[3])
	if len(buf) > 5 {
		bo.Name = string(buf[5:])
	}
}

func (bo *bsdpBootOption) ToID() []byte {
	res := make([]byte, 4)
	res[0] = bo.OSType
	if bo.Install {
		res[0] += 0x80
	}
	res[2] = byte(bo.Index >> 8)
	res[3] = byte(bo.Index)
	return res
}

func (bo *bsdpBootOption) ToOption() []byte {
	res := bo.ToID()
	if len(bo.Name) == 0 {
		return res
	}
	if len(bo.Name) < 255 {
		res = append(res, byte(len(bo.Name)))
		res = append(res, bo.Name[:]...)
		return res
	}
	res = append(res, 255)
	res = append(res, bo.Name[:255]...)
	return res
}

type BsdpBootOptions []*bsdpBootOption

func (bos BsdpBootOptions) ToOptions(budget int) []byte {
	res := []byte{0x09, 0x00}
	for i := range bos {
		buf := bos[i].ToOption()
		if len(buf)+len(res) > budget {
			break
		}
		res = append(res, buf...)
	}
	res[1] = byte(len(res) - 2)
	return res
}

func fillBsdpBootOptions(buf []byte) BsdpBootOptions {
	res := BsdpBootOptions{}
	for len(buf) > 4 {
		oLen := buf[4] + 5
		val := buf[:oLen]
		buf = buf[oLen:]
		bo := &bsdpBootOption{}
		bo.FromOption(val)
		res = append(res, bo)
	}
	return res
}

//option:code:43,
type bsdpOpts struct {
	msgtype       byte            //code 1 = uint8. 1 = LIST, 2 = SELECT, 3 = FAILED
	version       uint16          // code 2 = uint16. Value must be 0x0101
	srvID         net.IP          // code 3 = ip4 address, IP we respond from.
	prio          uint16          // code = 4, uint16 , priority of the server.  Higher is higher.
	replyPort     uint16          // code = 5, uint16, port to send reply to.  Defaults to 68.
	defaultImage  *bsdpBootOption // code = 7, uint32, ID of the default image to boot.
	selectedImage *bsdpBootOption // code = 8, uint32, ID of the selected image to boot.
	imageList     BsdpBootOptions // code = 9, list of available images in the following format:
}

func (o *bsdpOpts) Parse(dhr *DhcpRequest) {
	opts := dhr.pktOpts[43]
	for len(opts) > 2 {
		code := opts[0]
		codeLen := int(opts[1])
		if len(opts[2:]) < codeLen {
			return
		}
		opts = opts[2:]
		val := opts[:codeLen]
		opts = opts[codeLen:]
		switch code {
		case 1:
			o.msgtype = val[0]
		case 2:
			o.version = btouint16(val)
		case 3:
			o.srvID = net.IP(val)
		case 4:
			o.prio = btouint16(val)
		case 5:
			o.replyPort = btouint16(val)
		case 7:
			o.defaultImage = &bsdpBootOption{}
			o.defaultImage.FromOption(val)
		case 8:
			o.selectedImage = &bsdpBootOption{}
			o.selectedImage.FromOption(val)
		case 9:
			o.imageList = fillBsdpBootOptions(val)
		}
	}
	return
}

func (o *bsdpOpts) ToOption() []byte {
	res := []byte{}
	if o.msgtype > 0 {
		res = append(res, 0x01, 0x01, o.msgtype)
	}
	// version 1.1
	res = append(res, 0x02, 0x02, 0x01, 0x01)
	if len(o.srvID) > 0 {
		res = append(res, 0x03, 0x04)
		res = append(res, o.srvID...)
	}
	if o.prio > 0 {
		res = append(res, 0x04, 0x02, byte(o.prio>>8), byte(o.prio))
	}
	if o.defaultImage != nil {
		res = append(res, 0x07, 0x04)
		res = append(res, o.defaultImage.ToID()...)
	}
	if o.selectedImage != nil {
		res = append(res, 0x08, 0x04)
		res = append(res, o.selectedImage.ToID()...)
	}
	if len(o.imageList) > 0 {
		list := o.imageList.ToOptions(255 - len(res))
		res = append(res, list...)
	}
	return res
}

func (dhr *DhcpRequest) bsdpFromBootenv() *models.BsdpBootOption {
	img := &models.BsdpBootOption{}
	img.UnmarshalText([]byte("netboot:diags::1:dr-boot:ipxe.efi:"))
	if dhr.machine != nil && dhr.bootEnv != nil && dhr.bootEnv.Meta["AppleBsdp"] != "" {
		img.UnmarshalText([]byte(dhr.bootEnv.Meta["AppleBsdp"]))
		img.Booter = dhr.bootEnv.PathFor(path.Join("i386", img.Booter))
		if img.RootPath != "" {
			img.RootPath = fmt.Sprintf("http://%s:%d%s",
				dhr.srcAddr.String(),
				dhr.handler.bk.StaticPort,
				dhr.bootEnv.PathFor(img.RootPath))
		}
	}
	return img
}

func (dhr *DhcpRequest) buildAppleBsdpOptions(serverID net.IP) {
	img := dhr.bsdpFromBootenv()
	dhr.outOpts = dhcp.Options{}
	dhr.outOpts[dhcp.OptionTFTPServerName] = []byte(dhr.nextServer.String())
	dhr.outOpts[dhcp.OptionVendorClassIdentifier] = []byte("AAPLBSDPC")
	dhr.outOpts[dhcp.OptionBootFileName] = []byte(img.Booter)
	if img.RootPath != "" {
		dhr.outOpts[dhcp.OptionRootPath] = []byte(img.RootPath)
	}
}

func (dhr *DhcpRequest) offerAppleBoot() bool {
	if val, ok := dhr.pktOpts[dhcp.OptionVendorClassIdentifier]; ok &&
		strings.HasPrefix(string(val), "AAPLBSDPC/i386") {
		return true
	}
	return false
}

func (dhr *DhcpRequest) ServeAppleBSDP() string {
	req, _ := dhr.reqAddr(dhr.reqType)
	srvID := dhr.respondFrom(req)
	if !(dhr.reqType == dhcp.Inform && dhr.offerAppleBoot()) {
		dhr.Infof("%s: Ignoring DHCP %s from %s to the Apple BSDP service", dhr.xid(), dhr.reqType, req)
		return "Ignored"
	}
	opts := &bsdpOpts{}
	opts.Parse(dhr)
	l, s, _ := dhr.FakeLease(req)
	dhr.checkMachine(l, s)
	if dhr.bootEnv != nil && !dhr.bootEnv.NetBoot() {
		dhr.Infof("%s: BootEnv says to ignore NetBoot request from %s", dhr.xid(), req)
		return "Ignored"
	}
	dhr.offerNetBoot = true
	dhr.Infof("%s: Handling BSDP msg type %d from %s", dhr.xid(), opts.msgtype, req)
	switch opts.msgtype {
	case bsdpList:
		// Construct a list ACK, send it back.
		opts.defaultImage = (*bsdpBootOption)(dhr.bsdpFromBootenv())
		opts.imageList = BsdpBootOptions{opts.defaultImage}
		opts.srvID = srvID
		dhr.outOpts = dhcp.Options{}
		dhr.outOpts[dhcp.OptionVendorClassIdentifier] = []byte("AAPLBSDPC")
		dhr.outOpts[dhcp.OptionVendorSpecificInformation] = opts.ToOption()
		dhr.Reply(dhr.buildReply(dhcp.ACK, srvID, req))
	case bsdpSelect:
		if !bytes.Equal(opts.srvID, srvID) {
			return "Ignored"
		}
		// Add a notation in the applicable Lease, send it back.
		// For now, though, blatantly ignore things and always boot into ipxe
		dhr.buildAppleBsdpOptions(srvID)
		dhr.Reply(dhr.buildReply(dhcp.ACK, srvID, req))
	case bsdpFail:
		// Halt and catch fire
		dhr.Errorf("%s: BSDP handshake from %s failed", dhr.xid(), req)
		return "Ignored"
	default:
		dhr.Warnf("%s: Invalid BSDP option %d", dhr.xid(), opts.msgtype)
		return "Invalid BSDP option"
	}
	return "ACK"
}
