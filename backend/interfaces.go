package backend

import (
	"net"
	"strings"

	"github.com/digitalrebar/provision/models"
)

func (dt *DataTracker) GetInterfaces() ([]*models.Interface, error) {
	intfs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	dnsConf := dnsReadConfig("/etc/resolv.conf")
	ifs := make([]*models.Interface, 0, 0)
	iface, gw, _ := defaultIPByRoute()
	for _, intf := range intfs {
		if (intf.Flags & net.FlagLoopback) == net.FlagLoopback {
			continue
		}
		if (intf.Flags & net.FlagUp) != net.FlagUp {
			continue
		}
		if strings.HasPrefix(intf.Name, "veth") {
			continue
		}
		var sip string
		var firstIp string

		addrs, err := intf.Addrs()
		if err != nil {
			return nil, err
		}

		addrList := make([]string, 0, 0)
		for _, addr := range addrs {
			thisIP, _, _ := net.ParseCIDR(addr.String())
			// Only care about addresses that are not link-local.
			if !thisIP.IsGlobalUnicast() {
				continue
			}
			// Only deal with IPv4 for now.
			if thisIP.To4() == nil {
				continue
			}

			if firstIp == "" {
				firstIp = addr.String()
			}
			if dt.OurAddress != "" && dt.OurAddress == addr.String() {
				sip = addr.String()
			}
			addrList = append(addrList, addr.String())
		}

		if sip == "" {
			if firstIp == "" {
				continue
			}
			sip = firstIp
		}

		ii := &models.Interface{
			Name:          intf.Name,
			Index:         intf.Index,
			Addresses:     addrList,
			ActiveAddress: sip,
		}
		ii.DnsServers = dnsConf.servers
		ii.DnsDomain = strings.TrimRight(dnsConf.domain, ".")
		ii.ReadOnly = true
		if iface != nil && iface.Name == intf.Name && gw != nil {
			ii.Gateway = gw.String()
		}
		ifs = append(ifs, ii)
	}

	return ifs, nil
}
