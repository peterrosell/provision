package backend

import (
	"fmt"
	"math/big"
	"net"

	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/store"
)

// Reservation tracks persistent DHCP IP address reservations.
type Reservation struct {
	*models.Reservation
	validate
}

// SetReadOnly interface function to set the ReadOnly flag.
func (r *Reservation) SetReadOnly(b bool) {
	r.ReadOnly = b
}

// SaveClean interface function to clear validation fields
// and return object as a store.KeySaver for the data stores.
func (r *Reservation) SaveClean() store.KeySaver {
	mod := *r.Reservation
	mod.ClearValidation()
	return toBackend(&mod, r.rt)
}

// Indexes returns a map of indexes for Reservation.
func (r *Reservation) Indexes() map[string]index.Maker {
	fix := AsReservation
	res := index.MakeBaseIndexes(r)
	res["Addr"] = index.Make(
		false,
		"IP Address",
		func(i, j models.Model) bool {
			n, o := big.Int{}, big.Int{}
			n.SetBytes(fix(i).Addr.To16())
			o.SetBytes(fix(j).Addr.To16())
			return n.Cmp(&o) == -1
		},
		func(ref models.Model) (gte, gt index.Test) {
			addr := &big.Int{}
			addr.SetBytes(fix(ref).Addr.To16())
			return func(s models.Model) bool {
					o := big.Int{}
					o.SetBytes(fix(s).Addr.To16())
					return o.Cmp(addr) != -1
				},
				func(s models.Model) bool {
					o := big.Int{}
					o.SetBytes(fix(s).Addr.To16())
					return o.Cmp(addr) == 1
				}
		},
		func(s string) (models.Model, error) {
			addr := net.ParseIP(s)
			if addr == nil {
				return nil, fmt.Errorf("Invalid Address: %s", s)
			}
			res := fix(r.New())
			res.Addr = addr
			return res, nil
		})
	res["Token"] = index.Make(
		false,
		"string",
		func(i, j models.Model) bool { return fix(i).Token < fix(j).Token },
		func(ref models.Model) (gte, gt index.Test) {
			token := fix(ref).Token
			return func(s models.Model) bool {
					return fix(s).Token >= token
				},
				func(s models.Model) bool {
					return fix(s).Token > token
				}
		},
		func(s string) (models.Model, error) {
			res := fix(r.New())
			res.Token = s
			return res, nil
		})
	res["Strategy"] = index.Make(
		false,
		"string",
		func(i, j models.Model) bool { return fix(i).Strategy < fix(j).Strategy },
		func(ref models.Model) (gte, gt index.Test) {
			strategy := fix(ref).Strategy
			return func(s models.Model) bool {
					return fix(s).Strategy >= strategy
				},
				func(s models.Model) bool {
					return fix(s).Strategy > strategy
				}
		},
		func(s string) (models.Model, error) {
			res := fix(r.New())
			res.Strategy = s
			return res, nil
		})
	res["NextServer"] = index.Make(
		false,
		"IP Address",
		func(i, j models.Model) bool {
			n, o := big.Int{}, big.Int{}
			n.SetBytes(fix(i).NextServer.To16())
			o.SetBytes(fix(j).NextServer.To16())
			return n.Cmp(&o) == -1
		},
		func(ref models.Model) (gte, gt index.Test) {
			addr := &big.Int{}
			addr.SetBytes(fix(ref).NextServer.To16())
			return func(s models.Model) bool {
					o := big.Int{}
					o.SetBytes(fix(s).NextServer.To16())
					return o.Cmp(addr) != -1
				},
				func(s models.Model) bool {
					o := big.Int{}
					o.SetBytes(fix(s).NextServer.To16())
					return o.Cmp(addr) == 1
				}
		},
		func(s string) (models.Model, error) {
			addr := net.ParseIP(s)
			if addr == nil {
				return nil, fmt.Errorf("Invalid Address: %s", s)
			}
			res := fix(r.New())
			res.NextServer = addr
			return res, nil
		})
	return res
}

// New returns an empty Reservation object with the
// forceChange and RT fields from the calling object
// as store.KeySaver for use by the data stores.
func (r *Reservation) New() store.KeySaver {
	res := &Reservation{Reservation: &models.Reservation{}}
	if r.Reservation != nil && r.ChangeForced() {
		res.ForceChange()
	}
	res.rt = r.rt
	return res
}

// AsReservation converts a models.Model to a *Reservation.
func AsReservation(o models.Model) *Reservation {
	return o.(*Reservation)
}

// AsReservations converts a list of models.Model to a list of *Reservation.
func AsReservations(o []models.Model) []*Reservation {
	res := make([]*Reservation, len(o))
	for i := range o {
		res[i] = AsReservation(o[i])
	}
	return res
}

// OnChange is called by the data stores when a value changes to
// ensure the change is valid.  Errors abort the change.
func (r *Reservation) OnChange(oldThing store.KeySaver) error {
	old := AsReservation(oldThing)
	if r.Token != old.Token {
		r.Errorf("Token cannot change")
	}
	if r.Strategy != old.Strategy {
		r.Errorf("Strategy cannot change")
	}
	if r.Scoped != old.Scoped {
		r.Errorf("Scoped cannot change")
	}
	if r.Subnet != old.Subnet {
		r.Errorf("Subnet cannot change")
	}
	return r.MakeError(422, ValidationError, r)
}

// OnCreate is called by the data stores when creating a value.
// It validates the object relative to others and upon error
// aborts the create.
func (r *Reservation) OnCreate() error {
	subnets := AsSubnets(r.rt.stores("subnets").Items())
	var subnet *Subnet
	for i := range subnets {
		if !subnets[i].subnet().Contains(r.Addr) {
			continue
		}
		if !subnets[i].InSubnetRange(r.Addr) {
			r.Errorf("Address %s is a network or broadcast address for subnet %s", r.Addr.String(), subnets[i].Name)
		}
		subnet = subnets[i]
		if r.Scoped {
			r.Subnet = subnet.Name
		}
		break
	}
	if r.Scoped && subnet == nil {
		r.Errorf("Address %s is not in a defined Subnet, and Scoped is true.", r.Addr.String())
		return r.MakeError(422, ValidationError, r)
	}
	reservations := AsReservations(r.rt.stores("reservations").Items())
	for i := range reservations {
		if reservations[i].Addr.Equal(r.Addr) {
			continue
		}
		if !(reservations[i].Token == r.Token &&
			reservations[i].Strategy == r.Strategy) {
			continue
		}
		if !r.Scoped {
			r.Errorf("Reservation %s already has Strategy %s: Token %s", reservations[i].Key(), r.Strategy, r.Token)
			continue
		}
		if !reservations[i].Scoped {
			r.Errorf("Unscoped reservation %s already has Strategy %s: Token %s", reservations[i].Key(), r.Strategy, r.Token)
			continue
		}
		if subnet.subnet().Contains(reservations[i].Addr) {
			r.Errorf("Reservation %s in subnet %s already has Strategy %s: Token %s",
				reservations[i].Key(), subnet.Name, r.Strategy, r.Token)
		}
	}
	return r.MakeError(422, ValidationError, r)
}

// Validate ensures the object is valid.  Setting the
// available and valid flags as appropriate.
func (r *Reservation) Validate() {
	validateIP4(r, r.Addr)
	if r.NextServer != nil {
		validateMaybeZeroIP4(r, r.NextServer)
	}
	if r.Token == "" {
		r.Errorf("Reservation Token cannot be empty!")
	}
	if r.Strategy == "" {
		r.Errorf("Reservation Strategy cannot be empty!")
	}

	r.AddError(index.CheckUnique(r, r.rt.stores("reservations").Items()))
	r.SetValid()
	r.SetAvailable()
}

// BeforeSave validates the object and returns an error
// if the operation should be aborted.
func (r *Reservation) BeforeSave() error {
	r.Validate()
	if !r.Useable() {
		return r.MakeError(422, ValidationError, r)
	}
	return nil
}

// OnLoad is call by the data store initialize and
// validate a loaded Reservation.
func (r *Reservation) OnLoad() error {
	defer func() { r.rt = nil }()
	r.Fill()
	return r.BeforeSave()
}

var reservationLockMap = map[string][]string{
	"get":     {"reservations"},
	"create":  {"reservations:rw", "subnets"},
	"update":  {"reservations:rw"},
	"patch":   {"reservations:rw"},
	"delete":  {"reservations:rw"},
	"actions": {"reservations", "profiles", "params"},
}

// Locks returns a list of prefixes to lock for a specific action.
func (r *Reservation) Locks(action string) []string {
	return reservationLockMap[action]
}
