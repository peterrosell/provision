package backend

import (
	"errors"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"time"

	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/provision/store"
)

// Lease models a DHCP Lease
type Lease struct {
	*models.Lease
	validate
}

func (l *Lease) SetReadOnly(b bool) {
	l.ReadOnly = b
}

func (l *Lease) SaveClean() store.KeySaver {
	mod := *l.Lease
	mod.ClearValidation()
	return toBackend(&mod, l.rt)
}

func (l *Lease) Indexes() map[string]index.Maker {
	fix := AsLease
	res := index.MakeBaseIndexes(l)
	res["Addr"] = index.Maker{
		Unique: false,
		Type:   "IP Address",
		Less: func(i, j models.Model) bool {
			n, o := big.Int{}, big.Int{}
			n.SetBytes(fix(i).Addr.To16())
			o.SetBytes(fix(j).Addr.To16())
			return n.Cmp(&o) == -1
		},
		Tests: func(ref models.Model) (gte, gt index.Test) {
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
		Fill: func(s string) (models.Model, error) {
			ip := net.ParseIP(s)
			if ip == nil {
				return nil, errors.New("Addr must be an IP address")
			}
			lease := fix(l.New())
			lease.Addr = ip
			return lease, nil
		},
	}
	res["Token"] = index.Maker{
		Unique: false,
		Type:   "string",
		Less:   func(i, j models.Model) bool { return fix(i).Token < fix(j).Token },
		Eq:     func(i, j models.Model) bool { return fix(i).Token == fix(j).Token },
		Match:  func(i models.Model, re *regexp.Regexp) bool { return re.MatchString(fix(i).Token) },
		Tests: func(ref models.Model) (gte, gt index.Test) {
			token := fix(ref).Token
			return func(s models.Model) bool {
					return fix(s).Token >= token
				},
				func(s models.Model) bool {
					return fix(s).Token > token
				}
		},
		Fill: func(s string) (models.Model, error) {
			lease := fix(l.New())
			lease.Token = s
			return lease, nil
		},
	}
	res["Strategy"] = index.Maker{
		Unique: false,
		Type:   "string",
		Less:   func(i, j models.Model) bool { return fix(i).Strategy < fix(j).Strategy },
		Eq:     func(i, j models.Model) bool { return fix(i).Strategy == fix(j).Strategy },
		Match:  func(i models.Model, re *regexp.Regexp) bool { return re.MatchString(fix(i).Strategy) },
		Tests: func(ref models.Model) (gte, gt index.Test) {
			strategy := fix(ref).Strategy
			return func(s models.Model) bool {
					return fix(s).Strategy >= strategy
				},
				func(s models.Model) bool {
					return fix(s).Strategy > strategy
				}
		},
		Fill: func(s string) (models.Model, error) {
			lease := fix(l.New())
			lease.Strategy = s
			return lease, nil
		},
	}
	res["State"] = index.Maker{
		Unique: false,
		Type:   "string",
		Less:   func(i, j models.Model) bool { return fix(i).State < fix(j).State },
		Eq:     func(i, j models.Model) bool { return fix(i).State == fix(j).State },
		Match:  func(i models.Model, re *regexp.Regexp) bool { return re.MatchString(fix(i).State) },
		Tests: func(ref models.Model) (gte, gt index.Test) {
			strategy := fix(ref).State
			return func(s models.Model) bool {
					return fix(s).State >= strategy
				},
				func(s models.Model) bool {
					return fix(s).State > strategy
				}
		},
		Fill: func(s string) (models.Model, error) {
			lease := fix(l.New())
			lease.State = s
			return lease, nil
		},
	}
	res["ExpireTime"] = index.Maker{
		Unique: false,
		Type:   "Date/Time string",
		Less:   func(i, j models.Model) bool { return fix(i).ExpireTime.Before(fix(j).ExpireTime) },
		Tests: func(ref models.Model) (gte, gt index.Test) {
			expireTime := fix(ref).ExpireTime
			return func(s models.Model) bool {
					ttime := fix(s).ExpireTime
					return ttime.Equal(expireTime) || ttime.After(expireTime)
				},
				func(s models.Model) bool {
					return fix(s).ExpireTime.After(expireTime)
				}
		},
		Fill: func(s string) (models.Model, error) {
			t := &time.Time{}
			if err := t.UnmarshalText([]byte(s)); err != nil {
				return nil, fmt.Errorf("ExpireTime is not valid: %v", err)
			}
			lease := fix(l.New())
			lease.ExpireTime = *t
			return lease, nil
		},
	}
	return res
}

func (l *Lease) Subnet(rt *RequestTracker) *Subnet {
	subnets := rt.stores("subnets")
	for _, i := range subnets.Items() {
		subnet := AsSubnet(i)
		if subnet.subnet().Contains(l.Addr) {
			return subnet
		}
	}
	return nil
}

func (l *Lease) Reservation(rt *RequestTracker) *Reservation {
	r := rt.stores("reservations").Find(models.Hexaddr(l.Addr))
	if r == nil {
		return nil
	}
	return AsReservation(r)
}

func (l *Lease) New() store.KeySaver {
	res := &Lease{Lease: &models.Lease{}}
	if l.Lease != nil && l.ChangeForced() {
		res.ForceChange()
	}
	res.rt = l.rt
	return res
}

func AsLease(o models.Model) *Lease {
	return o.(*Lease)
}

func AsLeases(o []models.Model) []*Lease {
	res := make([]*Lease, len(o))
	for i := range o {
		res[i] = AsLease(o[i])
	}
	return res
}

func (l *Lease) OnCreate() error {
	if r := l.Reservation(l.rt); r != nil {
		return nil
	}
	if s := l.Subnet(l.rt); s == nil {
		l.Errorf("Cannot create Lease without a reservation or a subnet")
	} else if !s.InSubnetRange(l.Addr) {
		l.Errorf("Address %s is a network or broadcast address for subnet %s", l.Addr.String(), s.Name)
	}
	return l.MakeError(422, ValidationError, l)
}

func (l *Lease) OnChange(oldThing store.KeySaver) error {
	old := AsLease(oldThing)
	if l.Token != old.Token {
		l.Errorf("Token cannot change")
	}
	if l.Strategy != old.Strategy {
		l.Errorf("Strategy cannot change")
	}
	if l.State != old.State {
		l.Errorf("State cannot change")
	}
	return l.MakeError(422, ValidationError, l)
}

func (l *Lease) Validate() {
	idx := l.rt.stores("leases").Items()
	l.AddError(index.CheckUnique(l, idx))
	leases := AsLeases(idx)
	validateIP4(l, l.Addr)
	if l.State != "INVALID" {
		if l.Token == "" {
			l.Errorf("Lease Token cannot be empty!")
		}
		if l.Strategy == "" {
			l.Errorf("Lease Strategy cannot be empty!")
		}
		for i := range leases {
			if leases[i].Addr.Equal(l.Addr) {
				continue
			}
			if leases[i].Token == l.Token &&
				leases[i].Strategy == l.Strategy {
				l.Errorf("Lease %s alreay has Strategy %s: Token %s", leases[i].Key(), l.Strategy, l.Token)
				break
			}
		}
	}
	l.SetValid()
	l.SetAvailable()
}

func (l *Lease) BeforeSave() error {
	l.Validate()
	if !l.Useable() {
		return l.MakeError(422, ValidationError, l)
	}
	return nil
}

func (l *Lease) OnLoad() error {
	defer func() { l.rt = nil }()
	l.Fill()
	return l.BeforeSave()
}

var leaseLockMap = map[string][]string{
	"get":     {"leases"},
	"create":  {"leases:rw", "subnets", "reservations"},
	"update":  {"leases:rw"},
	"patch":   {"leases:rw"},
	"delete":  {"leases:rw"},
	"actions": {"leases", "profiles", "params"},
}

func (l *Lease) Locks(action string) []string {
	return leaseLockMap[action]
}
