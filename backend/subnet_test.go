package backend

import (
	"net"
	"testing"

	"github.com/digitalrebar/provision/models"
)

func TestSubnetCrud(t *testing.T) {
	dt := mkDT()
	rt := dt.Request(dt.Logger, "subnets", "leases", "reservations")
	createTests := []crudTest{
		{"Create empty Subnet", rt.Create, &models.Subnet{}, false},
		{"Create with bad name /", rt.Create, &models.Subnet{Name: "greg/24"}, false},
		{"Create with bad name \\", rt.Create, &models.Subnet{Name: "greg\\24"}, false},
		{"Create valid Subnet", rt.Create, &models.Subnet{Name: "test", Subnet: "192.168.124.0/24", ActiveStart: net.ParseIP("192.168.124.80"), ActiveEnd: net.ParseIP("192.168.124.254"), ActiveLeaseTime: 60, ReservedLeaseTime: 7200, Strategy: "mac"}, true},
		{"Create duplicate Subnet", rt.Create, &models.Subnet{Name: "test", Subnet: "192.168.124.0/24", ActiveStart: net.ParseIP("192.168.124.80"), ActiveEnd: net.ParseIP("192.168.124.254"), ActiveLeaseTime: 60, ReservedLeaseTime: 7200, Strategy: "mac"}, false},
		{"Create invalid Subnet(bad Subnet)", rt.Create, &models.Subnet{Name: "test2", Subnet: "127.0.0.0", ActiveStart: net.ParseIP("192.168.124.80"), ActiveEnd: net.ParseIP("192.168.124.254"), ActiveLeaseTime: 60, ReservedLeaseTime: 7200, Strategy: "mac"}, false},
		{"Create invalid Subnet(overlapping Subnet)", rt.Create, &models.Subnet{Name: "test2", Subnet: "192.168.124.0/24", ActiveStart: net.ParseIP("192.168.124.80"), ActiveEnd: net.ParseIP("192.168.124.254"), ActiveLeaseTime: 60, ReservedLeaseTime: 7200, Strategy: "mac"}, false},
		{"Create invalid Subnet(swapped Active range endpoints)", rt.Create, &models.Subnet{Name: "test2", Subnet: "192.168.125.0/24", ActiveStart: net.ParseIP("192.168.125.254"), ActiveEnd: net.ParseIP("192.168.125.80"), ActiveLeaseTime: 60, ReservedLeaseTime: 7200, Strategy: "mac"}, false},
		{"Create invalid Subnet(ActiveStart out of range)", rt.Create, &models.Subnet{Name: "test2", Subnet: "192.168.125.0/24", ActiveStart: net.ParseIP("192.168.124.80"), ActiveEnd: net.ParseIP("192.168.125.254"), ActiveLeaseTime: 60, ReservedLeaseTime: 7200, Strategy: "mac"}, false},
		{"Create invalid Subnet(ActiveEnd out of range)", rt.Create, &models.Subnet{Name: "test2", Subnet: "192.168.125.0/24", ActiveStart: net.ParseIP("192.168.125.80"), ActiveEnd: net.ParseIP("192.168.126.254"), ActiveLeaseTime: 60, ReservedLeaseTime: 7200, Strategy: "mac"}, false},
		{"Create invalid Subnet(ActiveLeaseTime too short)", rt.Create, &models.Subnet{Name: "test2", Subnet: "192.168.125.0/24", ActiveStart: net.ParseIP("192.168.125.80"), ActiveEnd: net.ParseIP("192.168.125.254"), ActiveLeaseTime: 59, ReservedLeaseTime: 7200, Strategy: "mac"}, false},
		{"Create invalid Subnet(ReservedLeaseTime too short)", rt.Create, &models.Subnet{Name: "test2", Subnet: "192.168.125.0/24", ActiveStart: net.ParseIP("192.168.125.80"), ActiveEnd: net.ParseIP("192.168.125.254"), ActiveLeaseTime: 60, ReservedLeaseTime: 7199, Strategy: "mac"}, false},
	}
	for _, test := range createTests {
		test.Test(t, rt)
	}
	// List test.
	rt.Do(func(d Stores) {
		bes := d("subnets").Items()
		if bes != nil {
			if len(bes) != 1 {
				t.Errorf("List function should have returned: 1, but got %d\n", len(bes))
			}
		} else {
			t.Errorf("List function returned nil!!")
		}
	})
}
