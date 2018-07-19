package backend

import (
	"net"
	"testing"
	"time"

	"github.com/digitalrebar/provision/models"
)

type ltf struct {
	msg             string
	strategy, token string
	req             net.IP
	found, err      bool
}

func (l *ltf) find(t *testing.T, rt *RequestTracker) {
	t.Helper()
	res, _, _, err := FindLease(rt, l.strategy, l.token, l.req)
	if l.found {
		if res == nil {
			t.Errorf("%s: Expected a lease for %s:%s, failed to get one", l.msg, l.strategy, l.token)
		} else if res.Strategy != l.strategy || res.Token != l.token {
			t.Errorf("%s: Expected lease to have %s:%s, has %s:%s", l.msg, l.strategy, l.token, res.Strategy, res.Token)
		} else if l.req != nil {
			if !res.Addr.Equal(l.req) {
				t.Errorf("%s: Expected lease %s:%s to have address %s, it has %s", l.msg, l.strategy, l.token, l.req, res.Addr)
			}
		} else {
			t.Logf("%s: Got lease %s:%s (%s)", l.msg, res.Strategy, res.Token, res.Addr)
		}
	} else {
		if res != nil {
			t.Errorf("%s: Did not expect to get lease, got %s:%s (%s)", l.msg, res.Strategy, res.Token, res.Addr)
		} else {
			t.Logf("%s: As expected, did not get lease for %s:%s", l.msg, l.strategy, l.token)
		}
	}
	if l.err {
		if err != nil {
			t.Logf("%s: Got expected error %#v", l.msg, err)
		} else {
			t.Errorf("%s: Did not get an error when we expected one!", l.msg)
		}
	} else {
		if err == nil {
			t.Logf("%s: No error expected or found", l.msg)
		} else {
			t.Errorf("%s: Got unexpected error %#v", l.msg, err)
		}
	}
}

func TestDHCPRenew(t *testing.T) {
	dt := mkDT(nil)
	rt := dt.Request(dt.Logger, "subnets", "reservations", "leases")
	startObjs := []crudTest{
		{
			"Initial Subnet",
			rt.Create,
			&models.Subnet{
				Enabled:           true,
				Name:              "sn",
				Subnet:            "192.168.124.0/24",
				ActiveStart:       net.ParseIP("192.168.124.80"),
				ActiveEnd:         net.ParseIP("192.168.124.254"),
				ActiveLeaseTime:   60,
				ReservedLeaseTime: 7200,
				Strategy:          "mac",
			},
			true,
		},
		{
			"Initial Standalone Reservation",
			rt.Create,
			&models.Reservation{Addr: net.ParseIP("192.168.123.10"), Token: "res1", Strategy: "mac"},
			true,
		},
		{
			"Valid Subnet Lease",
			rt.Create,
			&models.Lease{Addr: net.ParseIP("192.168.124.80"), Strategy: "mac", Token: "subn1", ExpireTime: time.Now().Add(60 * time.Second)},
			true,
		},
		{
			"Valid Reservation Lease",
			rt.Create,
			&models.Lease{Addr: net.ParseIP("192.168.123.10"), Strategy: "mac", Token: "res1", ExpireTime: time.Now().Add(2 * time.Hour)},
			true,
		},
		{
			"Conflicting Reservation Lease",
			rt.Create,
			&models.Lease{Addr: net.ParseIP("192.168.124.81"), Strategy: "mac", Token: "subn2", ExpireTime: time.Now().Add(2 * time.Hour)},
			true,
		},
		{
			"Overridden Reservation Lease",
			rt.Create,
			&models.Lease{Addr: net.ParseIP("192.168.124.82"), Strategy: "mac", Token: "res3", ExpireTime: time.Now().Add(60 * time.Second)},
			true,
		},
		{
			"Initial Conflicting Reservation",
			rt.Create,
			&models.Reservation{Addr: net.ParseIP("192.168.124.81"), Token: "res2", Strategy: "mac"},
			true,
		},
		{
			"Initial Overriding Reservation",
			rt.Create,
			&models.Reservation{Addr: net.ParseIP("192.168.124.83"), Token: "res3", Strategy: "mac"},
			true,
		},
	}
	for _, obj := range startObjs {
		obj.Test(t, rt)
	}
	ltfs := []ltf{
		{"Renew subnet lease using IP address", "mac", "subn1", net.ParseIP("192.168.124.80"), true, false},
		{"Renew reservation lease using IP address", "mac", "res1", net.ParseIP("192.168.123.10"), true, false},
		{"Fail to renew unknown lease using IP address in subnet", "mac", "res1", net.ParseIP("192.168.124.90"), false, true},
		{"Fail to renew known lease from wrong token", "mac", "subn8", net.ParseIP("192.168.124.80"), false, true},
		{"Fail to renew known lease from wrong address", "mac", "subn2", net.ParseIP("192.168.124.81"), false, true},
		{"Fail to renew lease overridden by new reserved address", "mac", "res3", net.ParseIP("192.168.124.82"), false, true},
	}
	for _, l := range ltfs {
		l.find(t, rt)
	}
	rt.Do(func(d Stores) {
		if ok, err := rt.Remove(&models.Reservation{Addr: net.ParseIP("192.168.123.10")}); !ok {
			t.Errorf("Failed to remove reservation for 192.168.123.10: %v", err)
		}
	})
	if l, _, _, err := FindLease(rt, "mac", "res1", net.ParseIP("192.168.123.10")); err == nil {
		t.Errorf("Should have removed lease for %s:%s, as its backing reservation is gone!", l.Strategy, l.Token)
	} else {
		t.Logf("Removed lease that no longer has a Subnet or Reservation covering it: %v", err)
	}
}

type ltc struct {
	msg             string
	strategy, token string
	req, via        net.IP
	created         bool
	expected        net.IP
}

func (l *ltc) test(t *testing.T, rt *RequestTracker) {
	t.Helper()
	res, _, _, _ := FindOrCreateLease(rt, l.strategy, l.token, l.req, []net.IP{l.via})
	if l.created {
		if res == nil {
			t.Errorf("%s: Expected to create a lease with %s:%s, but did not!", l.msg, l.strategy, l.token)
		} else if l.expected != nil && !res.Addr.Equal(l.expected) {
			t.Errorf("%s: Lease %s:%s got %s, expected %s", l.msg, l.strategy, l.token, res.Addr, l.expected)
		} else {
			t.Logf("%s: Created lease %s:%s: %s", l.msg, res.Strategy, res.Token, res.Addr)
		}
	} else {
		if res != nil {
			t.Errorf("%s: Did not expect to create lease %s:%s: %s", l.msg, l.strategy, l.token, res.Addr)
		} else {
			t.Logf("%s: No lease created, as expected", l.msg)
		}
	}
}

func TestDHCPCreateReservationOnly(t *testing.T) {
	dt := mkDT(nil)
	rt := dt.Request(dt.Logger, "subnets", "reservations", "leases")
	startObjs := []crudTest{
		{"Res1", rt.Create, &models.Reservation{Addr: net.ParseIP("192.168.123.10"), Token: "res1", Strategy: "mac"}, true},
		{"Res2", rt.Create, &models.Reservation{Addr: net.ParseIP("192.168.124.10"), Token: "res2", Strategy: "mac"}, true},
	}
	for _, obj := range startObjs {
		obj.Test(t, rt)
	}
	createTests := []ltc{
		{"Create lease from reservation Res1", "mac", "res1", nil, nil, true, net.ParseIP("192.168.123.10")},
		{"Attempt to create from wrong token for Res1", "mac", "resn", net.ParseIP("192.168.123.10"), nil, false, nil},
		{"Renew created lease for Res1", "mac", "res1", net.ParseIP("192.168.123.10"), nil, true, net.ParseIP("192.168.123.10")},
		{"Override requested address due to reservation", "mac", "res1", net.ParseIP("192.168.123.11"), nil, true, net.ParseIP("192.168.123.10")},
		{"Recreate with no requested address for Res1", "mac", "res1", nil, nil, true, net.ParseIP("192.168.123.10")},
		{"Attempt to create with no reservation", "mac", "resn", nil, nil, false, nil},
		{"Create lease from reservation Res2", "mac", "res2", nil, nil, true, net.ParseIP("192.168.124.10")},
	}
	for _, obj := range createTests {
		obj.test(t, rt)
	}
	func() {
		d, unlocker := dt.lockEnts("subnets", "reservations", "leases")
		defer unlocker()
		// Expire one lease
		lease := AsLease(d("leases").Find(models.Hexaddr(net.ParseIP("192.168.123.10"))))
		lease.ExpireTime = time.Now().Add(-2 * time.Second)
		lease.Token = "res3"
		// Make another refer to a different Token
		lease = AsLease(d("leases").Find(models.Hexaddr(net.ParseIP("192.168.124.10"))))
		lease.Token = "resn"
	}()
	renewTests := []ltc{
		{"Renew expired lease for Res1", "mac", "res1", nil, nil, true, net.ParseIP("192.168.123.10")},
		{"Fail to create lesase for Res2 when conflicting lease exists", "mac", "res2", nil, nil, false, nil},
	}
	for _, obj := range renewTests {
		obj.test(t, rt)
	}
}

func TestDHCPCreateSubnet(t *testing.T) {
	dt := mkDT(nil)
	rt := dt.Request(dt.Logger, "subnets", "leases", "reservations")
	var subnet *Subnet
	// A subnet with 3 active addresses
	startObjs := []crudTest{
		{"Create Subnet", rt.Create, &models.Subnet{Enabled: true, Name: "test", Subnet: "192.168.124.0/24", ActiveStart: net.ParseIP("192.168.124.80"), ActiveEnd: net.ParseIP("192.168.124.83"), ActiveLeaseTime: 60, ReservedLeaseTime: 7200, Strategy: "mac"}, true},
		{"Create Reservation", rt.Create, &models.Reservation{Addr: net.ParseIP("192.168.124.83"), Token: "res1", Strategy: "mac"}, true},
	}
	for _, obj := range startObjs {
		obj.Test(t, rt)
	}
	rt.Do(func(d Stores) {
		subnet = AsSubnet(rt.find("subnets", "test"))
	})
	subnet.Pickers = []string{"none"}
	// Even though there are no leases and no reservations, we should fail to create a lease.
	noneTests := []ltc{
		{"Fail to create lease for Sub1 when missing via", "mac", "sub1", nil, nil, false, nil},
		{"Fail to create lease for Sub1 when using wrong strategy", "mac2", "sub1", nil, net.ParseIP("192.168.124.1"), false, nil},
		{"Fail to create lease for Sub1 when requesting out-of-range address", "mac", "sub1", nil, net.ParseIP("192.168.124.1"), false, nil},
		{"Fail to create lease for Sub1 when Picker is none", "mac", "sub1", net.ParseIP("192.168.124.80"), net.ParseIP("192.168.124.1"), false, nil},
	}
	for _, obj := range noneTests {
		obj.test(t, rt)
	}

	subnet.Pickers = []string{"hint", "nextFree", "mostExpired"}
	subnet.nextLeasableIP = net.ParseIP("192.168.124.81")
	nextTests := []ltc{
		{"Create lease using pickHint picker", "mac", "sub1", net.ParseIP("192.168.124.81"), net.ParseIP("192.168.124.1"), true, net.ParseIP("192.168.124.81")},
		{"Fail to create lease using pickHint picker", "mac", "sub2", net.ParseIP("192.168.124.81"), net.ParseIP("192.168.124.1"), false, nil},
		{"Create lease using pickNextFree", "mac", "sub2", nil, net.ParseIP("192.168.124.1"), true, net.ParseIP("192.168.124.82")},
		{"Create lease using pickNextFree", "mac", "sub3", nil, net.ParseIP("192.168.124.1"), true, net.ParseIP("192.168.124.80")},
	}
	for _, obj := range nextTests {
		obj.test(t, rt)
	}
	rt.Do(func(d Stores) {
		lease := AsLease(rt.find("leases", models.Hexaddr(net.ParseIP("192.168.124.81"))))
		lease.ExpireTime = time.Now().Add(-2 * time.Second)
		lease = AsLease(rt.find("leases", models.Hexaddr(net.ParseIP("192.168.124.80"))))
		lease.ExpireTime = time.Now().Add(-2 * time.Hour)
		lease = AsLease(rt.find("leases", models.Hexaddr(net.ParseIP("192.168.124.82"))))
		lease.ExpireTime = time.Now().Add(-48 * time.Hour)
	})
	expireTests := []ltc{
		{"Refuse to create lease from requested addr due to conflicting reservation", "mac", "sub4", net.ParseIP("192.168.124.83"), net.ParseIP("192.168.124.1"), false, nil},
		{"Take over 2 day expired lease using pickHint", "mac", "sub4", net.ParseIP("192.168.124.82"), net.ParseIP("192.168.124.1"), true, net.ParseIP("192.168.124.82")},
		{"Refresh lease with requested address", "mac", "sub4", net.ParseIP("192.168.124.82"), net.ParseIP("192.168.124.1"), true, net.ParseIP("192.168.124.82")},
		{"Refresh lease without requested address", "mac", "sub4", nil, net.ParseIP("192.168.124.1"), true, net.ParseIP("192.168.124.82")},
		{"Take over 2 hour expired lease via pickMostExpired", "mac", "sub5", nil, net.ParseIP("192.168.124.1"), true, net.ParseIP("192.168.124.80")},
		{"Take over 2 second expired lease via pickMostExpired", "mac", "sub6", nil, net.ParseIP("192.168.124.1"), true, net.ParseIP("192.168.124.81")},
		{"Fail to get lease due to address range exhaustion", "mac", "sub7", nil, net.ParseIP("192.168.124.1"), false, nil},
		{"Create lease from reservation", "mac", "res1", nil, net.ParseIP("192.168.124.1"), true, net.ParseIP("192.168.124.83")},
	}
	for _, obj := range expireTests {
		obj.test(t, rt)
	}
}
