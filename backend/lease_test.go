package backend

import (
	"net"
	"testing"
	"time"

	"github.com/digitalrebar/provision/models"
)

func TestLeaseCrud(t *testing.T) {
	dt := mkDT()
	rt := dt.Request(dt.Logger, "leases:rw", "reservations", "subnets:rw")
	tests := []crudTest{
		{"Test Invalid Lease Create", rt.Create, &models.Lease{}, false},
		{"Test Incorrect IP Address Create", rt.Create, &models.Lease{Addr: net.ParseIP("127.0.0.1"), Token: "token", ExpireTime: time.Now(), Strategy: "token"}, false},
		{"Test EmptyToken Create", rt.Create, &models.Lease{Addr: net.ParseIP("192.168.124.10"), Token: "", ExpireTime: time.Now(), Strategy: "token"}, false},
		{"Test EmptyStrategy Create", rt.Create, &models.Lease{Addr: net.ParseIP("192.168.124.10"), Token: "token", ExpireTime: time.Now(), Strategy: ""}, false},
		{"Test Missing Subnet Create", rt.Create, &models.Lease{Addr: net.ParseIP("192.168.124.10"), Token: "token", Strategy: "token", ExpireTime: time.Now().Add(10 * time.Second)}, false},
		{"Create subnet for creating leases", rt.Create, &models.Subnet{Name: "test", Subnet: "192.168.124.0/24", ActiveStart: net.ParseIP("192.168.124.80"), ActiveEnd: net.ParseIP("192.168.124.254"), ActiveLeaseTime: 60, ReservedLeaseTime: 7200, Strategy: "noop"}, true},
		{"Test Valid Create", rt.Create, &models.Lease{Addr: net.ParseIP("192.168.124.10"), Token: "token", Strategy: "token", ExpireTime: time.Now().Add(10 * time.Second)}, true},
		{"Test Duplicate IP Create", rt.Create, &models.Lease{Addr: net.ParseIP("192.168.124.10"), Token: "token", Strategy: "token", ExpireTime: time.Now().Add(10 * time.Second)}, false},
		{"Test Duplicate Token Create", rt.Create, &models.Lease{Addr: net.ParseIP("192.168.124.11"), Token: "token", Strategy: "token", ExpireTime: time.Now().Add(10 * time.Second)}, false},
		{"Test Token Update", rt.Update, &models.Lease{Addr: net.ParseIP("192.168.124.10"), Token: "token2", Strategy: "token", ExpireTime: time.Now().Add(10 * time.Second)}, false},
		{"Test Strategy Update", rt.Update, &models.Lease{Addr: net.ParseIP("192.168.124.10"), Token: "token", Strategy: "token2", ExpireTime: time.Now().Add(10 * time.Second)}, false},
		{"Test Expire Update", rt.Update, &models.Lease{Addr: net.ParseIP("192.168.124.10"), Token: "token", Strategy: "token", ExpireTime: time.Now().Add(10 * time.Minute)}, true},
	}
	for _, test := range tests {
		test.Test(t, rt)
	}

	// List test.
	rt.Do(func(d Stores) {
		bes := d("leases").Items()
		if bes != nil {
			if len(bes) != 1 {
				t.Errorf("List function should have returned: 1, but got %d\n", len(bes))
			}
		} else {
			t.Errorf("List function returned nil!!")
		}

	})
}
