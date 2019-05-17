package midlayer

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/digitalrebar/logger"
	"github.com/digitalrebar/pinger"
	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/store"
)

var tmpDir string
var dataTracker *backend.DataTracker
var dhcpHandler, binlHandler *DhcpHandler

func makeHandler(dt *backend.DataTracker, proxy bool) *DhcpHandler {
	port := 67
	if proxy {
		port = 4011
	}
	res := &DhcpHandler{
		Logger:   logger.New(nil).Log("dhcp"),
		ifs:      []string{},
		port:     port,
		bk:       dt,
		strats:   []*Strategy{{Name: "MAC", GenToken: MacStrategy}},
		pinger:   pinger.Fake(true),
		binlOnly: proxy,
	}
	return res
}

func fakeServer() error {
	baseLog := log.New(os.Stdout, "dt", 0)
	l := logger.New(baseLog).Log("backend")
	ss, _ := store.Open("memory:///")
	s, err := backend.DefaultDataStack("", "memory:///", "", "", "", tmpDir, l, nil)
	if err != nil {
		panic("Cannot happen")
	}
	dataTracker = backend.NewDataTracker(s,
		ss,
		tmpDir,
		tmpDir,
		"127.0.0.1",
		false,
		8091,
		8092,
		"fred",
		l,
		map[string]string{"systemGrantorSecret": "itisfred", "defaultStage": "none", "defaultBootEnv": "local", "unknownBootEnv": "ignore"},
		backend.NewPublishers(baseLog))
	dhcpHandler = makeHandler(dataTracker, false)
	binlHandler = makeHandler(dataTracker, true)
	rt := dataTracker.Request(l, "subnets:rw")
	var gerr error
	rt.Do(func(d backend.Stores) {
		subs := []*models.Subnet{
			// Normal DHCP network.
			{
				Name:              "sub1",
				Enabled:           true,
				Subnet:            "192.168.124.1/24",
				ActiveStart:       net.IPv4(192, 168, 124, 10),
				ActiveEnd:         net.IPv4(192, 168, 124, 15),
				ReservedLeaseTime: 7200,
				ActiveLeaseTime:   60,
				Strategy:          "MAC",
				Options: []models.DhcpOption{
					{Code: 3, Value: "192.168.124.1"},
					{Code: 6, Value: "192.168.124.1"},
					{Code: 15, Value: "sub1.com"},
				},
			},
			// DHCP via a gateway
			{
				Name:              "sub2",
				Enabled:           true,
				Subnet:            "172.17.0.8/24",
				ActiveStart:       net.IPv4(172, 17, 0, 10),
				ActiveEnd:         net.IPv4(172, 17, 0, 15),
				ReservedLeaseTime: 7200,
				ActiveLeaseTime:   60,
				Strategy:          "MAC",
				Options: []models.DhcpOption{
					{Code: 3, Value: "172.17.0.1"},
					{Code: 6, Value: "172.17.0.1"},
					{Code: 15, Value: "sub2.com"},
				},
			},
			// ProxyDHCP network.
			{
				Name:              "sub3",
				Enabled:           true,
				Proxy:             true,
				Subnet:            "10.0.0.0/8",
				ReservedLeaseTime: 7200,
				ActiveLeaseTime:   60,
				Strategy:          "MAC",
				Options: []models.DhcpOption{
					{Code: 3, Value: "10.0.0.1"},
					{Code: 6, Value: "10.0.0.1"},
					{Code: 15, Value: "sub1.com"},
				},
			},
		}
		for _, sub := range subs {
			_, err := rt.Create(sub)
			if err != nil {
				gerr = fmt.Errorf("Error creating subnet %s: %v", sub.Name, err)
			}
		}
	})
	return gerr
}
