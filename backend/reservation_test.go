package backend

import (
	"net"
	"testing"

	"github.com/digitalrebar/provision/models"
)

func TestReservationCrud(t *testing.T) {
	dt := mkDT()
	rt := dt.Request(dt.Logger, "reservations", "subnets")
	tests := []crudTest{
		{"Test Invalid Reservation Create", rt.Create, &models.Reservation{}, false},
		{"Test Incorrect IP Address Create", rt.Create, &models.Reservation{Addr: net.ParseIP("127.0.0.1"), Token: "token", Strategy: "token"}, false},
		{"Test EmptyToken Create", rt.Create, &models.Reservation{Addr: net.ParseIP("192.168.124.10"), Token: "", Strategy: "token"}, false},
		{"Test EmptyStrategy Create", rt.Create, &models.Reservation{Addr: net.ParseIP("192.168.124.10"), Token: "token", Strategy: ""}, false},
		{"Test Valid Create", rt.Create, &models.Reservation{Addr: net.ParseIP("192.168.124.10"), Token: "token", Strategy: "token"}, true},
		{"Test Duplicate IP Create", rt.Create, &models.Reservation{Addr: net.ParseIP("192.168.124.10"), Token: "token", Strategy: "token"}, false},
		{"Test Duplicate Token Create", rt.Create, &models.Reservation{Addr: net.ParseIP("192.168.124.11"), Token: "token", Strategy: "token"}, false},
		{"Test Token Update", rt.Update, &models.Reservation{Addr: net.ParseIP("192.168.124.10"), Token: "token2", Strategy: "token"}, false},
		{"Test Strategy Update", rt.Update, &models.Reservation{Addr: net.ParseIP("192.168.124.10"), Token: "token", Strategy: "token2"}, false},
		{"Test Expire Update", rt.Update, &models.Reservation{Addr: net.ParseIP("192.168.124.10"), Token: "token", Strategy: "token"}, true},
	}
	for _, test := range tests {
		test.Test(t, rt)
	}
	rt.Do(func(d Stores) {
		// List test.
		bes := d("reservations").Items()
		if bes != nil {
			if len(bes) != 1 {
				t.Errorf("List function should have returned: 1, but got %d\n", len(bes))
			}
		} else {
			t.Errorf("List function returned nil!!")
		}
	})
}
