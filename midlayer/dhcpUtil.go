package midlayer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/ipv4"

	"github.com/digitalrebar/logger"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/provision/utils"
	dhcp "github.com/krolaw/dhcp4"
)

func (dhr *DhcpRequest) marshalText(p dhcp.Packet) ([]byte, error) {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "proto:dhcp4 iface:%s ifaddr:%s lport:%d\n",
		dhr.ifname(),
		dhr.srcAddr.String(),
		dhr.lPort)
	fmt.Fprintf(buf, "op:%#02x htype:%#02x hlen:%#02x hops:%#02x xid:%#08x secs:%#04x flags:%#04x\n",
		p.OpCode(),
		p.HType(),
		p.HLen(),
		p.Hops(),
		binary.BigEndian.Uint32(p.XId()),
		binary.BigEndian.Uint16(p.Secs()),
		binary.BigEndian.Uint16(p.Flags()))
	fmt.Fprintf(buf, "ci:%s yi:%s si:%s gi:%s ch:%s\n",
		p.CIAddr(),
		p.YIAddr(),
		p.SIAddr(),
		p.GIAddr(),
		p.CHAddr())
	if sname := string(p.SName()); len(sname) != 0 {
		fmt.Fprintf(buf, "sname:%q\n", sname)
	}
	if fname := string(p.File()); len(fname) != 0 {
		fmt.Fprintf(buf, "file:%q\n", fname)
	}
	opts, err := models.DHCPOptionsInOrder(p)
	for _, opt := range opts {
		fmt.Fprintf(buf, "option:%s\n", opt)
	}
	return buf.Bytes(), err
}

func (dhr *DhcpRequest) MarshalText() ([]byte, error) {
	return dhr.marshalText(dhr.request)
}

func (dhr *DhcpRequest) PrintIncoming() string {
	buf, err := dhr.MarshalText()
	if err != nil {
		dhr.Errorf("Error processing options: %v", err)
		return string(buf) + "\n" + err.Error()
	}
	return string(buf)
}

func (dhr *DhcpRequest) PrintOutgoing(p dhcp.Packet) string {
	if p == nil || len(p) == 0 {
		return ""
	}
	buf, err := dhr.marshalText(p)
	if err != nil {
		dhr.Errorf("Error processing options: %v", err)
		return string(buf) + "\n" + err.Error()
	}
	return string(buf)
}

func (dhr *DhcpRequest) UnmarshalText(buf []byte) error {
	res := dhcp.NewPacket(dhcp.OpCode(0))
	lines := strings.Split(
		strings.TrimSpace(string(buf)), "\n")
	if len(lines) < 3 ||
		!strings.HasPrefix(lines[0], "proto:dhcp4") ||
		!strings.HasPrefix(lines[1], "op:") ||
		!strings.HasPrefix(lines[2], "ci:") {
		return fmt.Errorf("Malformed DHCP packet")
	}
	var (
		intf, intfaddr string
		lport          int
	)
	count, err := fmt.Sscanf(lines[0], "proto:dhcp4 iface:%s ifaddr:%s lport:%d", &intf, &intfaddr, &lport)
	if err != nil || count != 3 {
		return fmt.Errorf("Error scanning packet line 0: %v", err)
	}
	dhr.lPort = lport
	dhr.cm = &ipv4.ControlMessage{}
	for idx, intfname := range dhr.nameMap {
		if intfname == intf {
			dhr.cm.IfIndex = idx
		}
	}
	dhr.srcAddr, err = net.ResolveUDPAddr("udp4", intfaddr)
	if err != nil {
		return fmt.Errorf("Malformed interface address %v", err)
	}
	dhr.cm.Src = dhr.srcAddr.(*net.UDPAddr).IP
	var (
		opcode, htype, hlen, hops byte
		secs, flags               uint16
		xid                       uint32
	)
	count, err = fmt.Sscanf(lines[1], "op:0x%02x htype:0x%02x hlen:0x%02x hops:0x%02x xid:0x%08x secs:0x%04x flags:0x%04x",
		&opcode, &htype, &hlen, &hops, &xid, &secs, &flags)
	if err != nil || count != 7 {
		return fmt.Errorf("Error scanning packet line 1: %v", err)
	}
	res.SetOpCode(dhcp.OpCode(opcode))
	res.SetHType(htype)
	res.SetHops(hops)
	buf2 := make([]byte, 2)
	buf4 := make([]byte, 4)
	binary.BigEndian.PutUint16(buf2, secs)
	res.SetSecs(buf2)
	binary.BigEndian.PutUint16(buf2, flags)
	res.SetFlags(buf2)
	binary.BigEndian.PutUint32(buf4, xid)
	res.SetXId(buf4)
	var (
		ci, yi, si, gi, ch string
	)
	count, err = fmt.Sscanf(lines[2], "ci:%s yi:%s si:%s gi:%s ch:%s",
		&ci, &yi, &si, &gi, &ch)
	if err != nil || count != 5 {
		return fmt.Errorf("Error scanning packet line 2: %v", err)
	}
	res.SetCIAddr(net.ParseIP(ci).To4())
	res.SetYIAddr(net.ParseIP(yi).To4())
	res.SetSIAddr(net.ParseIP(si).To4())
	res.SetGIAddr(net.ParseIP(gi).To4())
	mac, err := net.ParseMAC(ch)
	if err != nil {
		return fmt.Errorf("malformed mac %s: %v", ch, err)
	}
	res.SetCHAddr(mac)
	if len(lines) == 3 {
		dhr.request = res
		return nil
	}
	for _, line := range lines[3:] {
		op := strings.SplitN(line, ":", 2)
		if len(op) != 2 {
			return fmt.Errorf("Badly formatted line %s", line)
		}
		switch op[0] {
		case "sname":
			sname := ""
			fmt.Sscanf(op[1], "%q", &sname)
			res.SetSName([]byte(sname))
		case "file":
			fname := ""
			fmt.Sscanf(op[1], "%q", &fname)
			res.SetFile([]byte(fname))
		case "option":
			var (
				code byte
				cval string
			)
			_, err := fmt.Sscanf(op[1], "code:%03d val:%q", &code, &cval)
			if err != nil {
				return fmt.Errorf("Error scanning option %s: %v", line, err)
			}
			opt := &models.DhcpOption{Code: code}
			if err := opt.Fill(cval); err != nil {
				return fmt.Errorf("invalid option %s: %v", line, err)
			}
			opt.AddToPacket(&res)
		}
	}
	dhr.request = res
	return nil
}

type DhcpMetrics struct {
	p *utils.Prometheus
}

func NewDhcpMetrics(l logger.Logger, binlOnly bool) *DhcpMetrics {
	ss := "drp_dhcp"
	if binlOnly {
		ss = "drp_binl"
	}
	mets := []*utils.Metric{
		{
			ID:          "reqCnt",
			Name:        "requests_total",
			Description: "How many DHCP requests processed, partitioned by type.",
			Type:        "counter_vec",
			Args:        []string{"type"},
		},
		{
			ID:          "resCnt",
			Name:        "replies_total",
			Description: "How many DHCP replies sent, partitioned by type.",
			Type:        "counter_vec",
			Args:        []string{"type"},
		},
		{
			ID:          "reqDur",
			Name:        "request_duration_seconds",
			Description: "The DHCP request latencies in seconds.",
			Type:        "summary",
		},
		{
			ID:          "resSz",
			Name:        "response_size_bytes",
			Description: "The DHCP response sizes in bytes.",
			Type:        "summary",
		},
		{
			ID:          "reqSz",
			Name:        "request_size_bytes",
			Description: "The DHCP request sizes in bytes.",
			Type:        "summary",
		},
	}
	return &DhcpMetrics{p: utils.NewPrometheus(l, ss, mets)}
}

func (dm *DhcpMetrics) CountPacket(count, elapsed float64, res dhcp.Packet, reqType, resType string) {
	dm.p.Observe("reqDur", elapsed)
	dm.p.Observe("reqSz", count)
	dm.p.CounterWithLabelValues("reqCnt", reqType).Inc()
	resSz := float64(0)
	if res != nil {
		resSz = float64(len(res))
	}
	dm.p.Observe("resSz", resSz)
	dm.p.CounterWithLabelValues("resCnt", resType).Inc()
}
