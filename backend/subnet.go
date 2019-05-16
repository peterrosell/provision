package backend

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sort"
	"time"

	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/store"
	dhcp "github.com/krolaw/dhcp4"
)

type picker func(*Subnet, map[string]models.Model, string, net.IP, net.IP) (*Lease, bool)

func pickNone(s *Subnet, usedAddrs map[string]models.Model, token string, hint, via net.IP) (*Lease, bool) {
	// There are no free addresses, and don't fall through to using the most expired one.
	return nil, false
}

func pickMostExpired(s *Subnet, usedAddrs map[string]models.Model, token string, hint, via net.IP) (*Lease, bool) {
	currLeases := []*Lease{}
	for _, obj := range usedAddrs {
		lease, ok := obj.(*Lease)
		if ok {
			currLeases = append(currLeases, lease)
		}
	}
	sort.Slice(currLeases,
		func(i, j int) bool {
			return currLeases[i].ExpireTime.Before(currLeases[j].ExpireTime)
		})
	for _, lease := range currLeases {
		if !lease.Expired() {
			// If we got to a non-expired lease, we are done
			break
		}
		// Because if how usedAddrs is built, we are guaranteed that an expired
		// lease here is not associated with a reservation.
		lease.Token = token
		lease.Strategy = s.Strategy
		return lease, false
	}
	return nil, true
}

func pickHint(s *Subnet, usedAddrs map[string]models.Model, token string, hint, via net.IP) (*Lease, bool) {
	if hint == nil || !s.InActiveRange(hint) {
		return nil, true
	}
	hex := models.Hexaddr(hint)
	res, found := usedAddrs[hex]
	if !found {
		lease := &Lease{}
		Fill(lease)
		lease.Addr, lease.Token, lease.Strategy = hint, token, s.Strategy
		return lease, false
	}
	if lease, ok := res.(*Lease); ok {
		if lease.Token == token && lease.Strategy == s.Strategy {
			// hey, we already have a lease.  How nice.
			return lease, false
		}
		if lease.Expired() {
			// We don't own this lease, but it is
			// expired, so we can steal it.
			lease.Token = token
			lease.Strategy = s.Strategy
			return lease, false
		}
	}
	return nil, false
}

func pickNextFree(s *Subnet, usedAddrs map[string]models.Model, token string, hint, via net.IP) (*Lease, bool) {
	if s.nextLeasableIP == nil {
		s.nextLeasableIP = net.IP(make([]byte, 4))
		copy(s.nextLeasableIP, s.ActiveStart.To4())
	}
	one := big.NewInt(1)
	end := &big.Int{}
	curr := &big.Int{}
	end.SetBytes(s.ActiveEnd.To4())
	curr.SetBytes(s.nextLeasableIP.To4())
	// First, check from nextLeasableIp to ActiveEnd
	for curr.Cmp(end) < 1 {
		addr := net.IP(curr.Bytes()).To4()
		hex := models.Hexaddr(addr)
		curr.Add(curr, one)
		if _, ok := usedAddrs[hex]; !ok {
			s.nextLeasableIP = addr
			lease := &Lease{}
			Fill(lease)
			lease.Addr, lease.Token, lease.Strategy = addr, token, s.Strategy
			return lease, false
		}
	}
	// Next, check from ActiveStart to nextLeasableIP
	end.SetBytes(s.nextLeasableIP.To4())
	curr.SetBytes(s.ActiveStart.To4())
	for curr.Cmp(end) < 1 {
		addr := net.IP(curr.Bytes()).To4()
		hex := models.Hexaddr(addr)
		curr.Add(curr, one)
		if _, ok := usedAddrs[hex]; !ok {
			s.nextLeasableIP = addr
			lease := &Lease{}
			Fill(lease)
			lease.Addr, lease.Token, lease.Strategy = addr, token, s.Strategy
			return lease, false
		}
	}
	// No free address, but we can use the most expired one.
	return nil, true
}

func pickPoint2Point(s *Subnet, usedAddrs map[string]models.Model, token string, hint, via net.IP) (*Lease, bool) {
	mask := big.NewInt(1)
	other := &big.Int{}
	if v2 := via.To4(); v2 == nil {
		other.SetBytes(via)
	} else {
		other.SetBytes(v2)
	}
	other = other.Xor(mask, other)
	addr := net.IP(other.Bytes())
	if !s.InActiveRange(addr) {
		return nil, true
	}
	lease := &Lease{}
	Fill(lease)
	lease.Addr = addr
	lease.Token = token
	lease.Strategy = s.Strategy
	return lease, false
}

var (
	pickStrategies = map[string]picker{}
)

func init() {
	pickStrategies["none"] = pickNone
	pickStrategies["hint"] = pickHint
	pickStrategies["nextFree"] = pickNextFree
	pickStrategies["mostExpired"] = pickMostExpired
	pickStrategies["point2point"] = pickPoint2Point
}

// Subnet represents a DHCP Subnet
type Subnet struct {
	*models.Subnet
	validate
	nextLeasableIP net.IP
	sn             *net.IPNet
}

// SetReadOnly is an interface function to set the ReadOnly flag.
func (s *Subnet) SetReadOnly(b bool) {
	s.ReadOnly = b
}

// SaveClean clears the validation fields and returns the object
// as a store.KeySaver for use by the backing store.
func (s *Subnet) SaveClean() store.KeySaver {
	mod := *s.Subnet
	mod.ClearValidation()
	return toBackend(&mod, s.rt)
}

// Indexes returns a map of the valid indexes for Subnet.
func (s *Subnet) Indexes() map[string]index.Maker {
	fix := AsSubnet
	res := index.MakeBaseIndexes(s)
	res["Name"] = index.Make(
		true,
		"string",
		func(i, j models.Model) bool { return fix(i).Name < fix(j).Name },
		func(ref models.Model) (gte, gt index.Test) {
			refName := fix(ref).Name
			return func(s models.Model) bool {
					return fix(s).Name >= refName
				},
				func(s models.Model) bool {
					return fix(s).Name > refName
				}
		},
		func(st string) (models.Model, error) {
			sub := fix(s.New())
			sub.Name = st
			return sub, nil
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
		func(st string) (models.Model, error) {
			sub := fix(s.New())
			sub.Strategy = st
			return sub, nil
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
		func(st string) (models.Model, error) {
			addr := net.ParseIP(st)
			if addr == nil {
				return nil, fmt.Errorf("Invalid Address: %s", st)
			}
			sub := fix(s.New())
			sub.NextServer = addr
			return sub, nil
		})
	res["Subnet"] = index.Make(
		true,
		"CIDR Address",
		func(i, j models.Model) bool {
			a, _, errA := net.ParseCIDR(fix(i).Subnet.Subnet)
			b, _, errB := net.ParseCIDR(fix(j).Subnet.Subnet)
			if errA != nil || errB != nil {
				fix(i).rt.Panicf("Illegal Subnets '%s', '%s'", fix(i).Subnet.Subnet, fix(j).Subnet.Subnet)
			}
			n, o := big.Int{}, big.Int{}
			n.SetBytes(a.To16())
			o.SetBytes(b.To16())
			return n.Cmp(&o) == -1
		},
		func(ref models.Model) (gte, gt index.Test) {
			cidr, _, err := net.ParseCIDR(fix(ref).Subnet.Subnet)
			if err != nil {
				fix(ref).rt.Panicf("Illegal subnet %s: %v", fix(ref).Subnet.Subnet, err)
			}
			addr := &big.Int{}
			addr.SetBytes(cidr.To16())
			return func(s models.Model) bool {
					cidr, _, err := net.ParseCIDR(fix(s).Subnet.Subnet)
					if err != nil {
						fix(s).rt.Panicf("Illegal subnet %s: %v", fix(s).Subnet.Subnet, err)
					}
					o := big.Int{}
					o.SetBytes(cidr.To16())
					return o.Cmp(addr) != -1
				},
				func(s models.Model) bool {
					cidr, _, err := net.ParseCIDR(fix(s).Subnet.Subnet)
					if err != nil {
						fix(s).rt.Panicf("Illegal subnet %s: %v", fix(s).Subnet.Subnet, err)
					}
					o := big.Int{}
					o.SetBytes(cidr.To16())
					return o.Cmp(addr) == 1
				}
		},
		func(st string) (models.Model, error) {
			if _, _, err := net.ParseCIDR(st); err != nil {
				return nil, fmt.Errorf("Invalid subnet CIDR: %s", st)
			}
			sub := fix(s.New())
			sub.Subnet.Subnet = st
			return sub, nil
		})
	res["Address"] = index.Make(
		false,
		"IP Address",
		func(i, j models.Model) bool {
			a, _, errA := net.ParseCIDR(fix(i).Subnet.Subnet)
			b, _, errB := net.ParseCIDR(fix(j).Subnet.Subnet)
			if errA != nil || errB != nil {
				fix(i).rt.Panicf("Illegal Subnets '%s', '%s'", fix(i).Subnet.Subnet, fix(j).Subnet.Subnet)
			}
			n, o := big.Int{}, big.Int{}
			n.SetBytes(a.To16())
			o.SetBytes(b.To16())
			return n.Cmp(&o) == -1
		},
		func(ref models.Model) (gte, gt index.Test) {
			addr := fix(ref).Subnet.Subnet
			if net.ParseIP(addr) == nil {
				fix(ref).rt.Panicf("Illegal IP Address: %s", addr)
			}
			return func(s models.Model) bool {
					l, _ := fix(s).sBounds()
					return l(addr)
				},
				func(s models.Model) bool {
					_, u := fix(s).sBounds()
					return u(addr)
				}
		},
		func(st string) (models.Model, error) {
			addr := net.ParseIP(st)
			if addr == nil {
				return nil, fmt.Errorf("Invalid IP address: %s", st)
			}
			sub := fix(s.New())
			sub.Subnet.Subnet = st
			return sub, nil
		})
	res["ActiveAddress"] = index.Make(
		false,
		"IP Address",
		func(i, j models.Model) bool {
			a, _, errA := net.ParseCIDR(fix(i).Subnet.Subnet)
			b, _, errB := net.ParseCIDR(fix(j).Subnet.Subnet)
			if errA != nil || errB != nil {
				fix(i).rt.Panicf("Illegal Subnets '%s', '%s'", fix(i).Subnet.Subnet, fix(j).Subnet.Subnet)
			}
			n, o := big.Int{}, big.Int{}
			n.SetBytes(a.To16())
			o.SetBytes(b.To16())
			return n.Cmp(&o) == -1
		},
		func(ref models.Model) (gte, gt index.Test) {
			addr := fix(ref).Subnet.Subnet
			if net.ParseIP(addr) == nil {
				fix(ref).rt.Panicf("Illegal IP Address: %s", addr)
			}
			return func(s models.Model) bool {
					l, _ := fix(s).aBounds()
					return l(addr)
				},
				func(s models.Model) bool {
					_, u := fix(s).aBounds()
					return u(addr)
				}
		},
		func(st string) (models.Model, error) {
			addr := net.ParseIP(st)
			if addr == nil {
				return nil, fmt.Errorf("Invalid IP address: %s", st)
			}
			sub := fix(s.New())
			sub.Subnet.Subnet = st
			return sub, nil
		})
	res["Enabled"] = index.Make(
		false,
		"boolean",
		func(i, j models.Model) bool {
			return (!fix(i).Enabled) && fix(j).Enabled
		},
		func(ref models.Model) (gte, gt index.Test) {
			avail := fix(ref).Enabled
			return func(s models.Model) bool {
					v := fix(s).Enabled
					return v || (v == avail)
				},
				func(s models.Model) bool {
					return fix(s).Enabled && !avail
				}
		},
		func(st string) (models.Model, error) {
			res := &Subnet{Subnet: &models.Subnet{}}
			switch st {
			case "true":
				res.Enabled = true
			case "false":
				res.Enabled = false
			default:
				return nil, errors.New("Enabled must be true or false")
			}
			return res, nil
		})
	res["Proxy"] = index.Make(
		false,
		"boolean",
		func(i, j models.Model) bool {
			return (!fix(i).Proxy) && fix(j).Proxy
		},
		func(ref models.Model) (gte, gt index.Test) {
			avail := fix(ref).Proxy
			return func(s models.Model) bool {
					v := fix(s).Proxy
					return v || (v == avail)
				},
				func(s models.Model) bool {
					return fix(s).Proxy && !avail
				}
		},
		func(st string) (models.Model, error) {
			res := &Subnet{Subnet: &models.Subnet{}}
			switch st {
			case "true":
				res.Proxy = true
			case "false":
				res.Proxy = false
			default:
				return nil, errors.New("Proxy must be true or false")
			}
			return res, nil
		})
	return res
}

func (s *Subnet) subnet() *net.IPNet {
	if s.sn != nil {
		return s.sn
	}
	_, res, err := net.ParseCIDR(s.Subnet.Subnet)
	if err != nil {
		panic(err.Error())
	}
	s.sn = res
	return res
}

// New returns a new Subnet with the forceChange and RT
// fields copied from the calling Subnet.
func (s *Subnet) New() store.KeySaver {
	res := &Subnet{Subnet: &models.Subnet{}}
	if s.Subnet != nil && s.ChangeForced() {
		res.ForceChange()
	}
	res.rt = s.rt
	return res
}

func (s *Subnet) sbounds() (net.IP, net.IP) {
	sub := s.subnet()
	first := big.NewInt(0)
	mask := big.NewInt(0)
	last := big.NewInt(0)
	first.SetBytes([]byte(sub.IP.Mask(sub.Mask)))
	notBits := make([]byte, len(sub.Mask))
	for i, b := range sub.Mask {
		notBits[i] = ^b
	}
	mask.SetBytes(notBits)
	last.Or(first, mask)
	return net.IP(first.Bytes()), net.IP(last.Bytes())
}

func (s *Subnet) sBounds() (func(string) bool, func(string) bool) {
	lb, ub := s.sbounds()
	// first "address" in this range is the network address, which cannot be handed out.
	lower := func(key string) bool {
		return key > models.Hexaddr(lb)
	}
	// last "address" in this range is the broadcast address, which also cannot be handed out.
	upper := func(key string) bool {
		return key >= models.Hexaddr(ub)
	}
	return lower, upper
}

func (s *Subnet) aBounds() (func(string) bool, func(string) bool) {
	return func(key string) bool {
			return key >= models.Hexaddr(s.ActiveStart)
		},
		func(key string) bool {
			return key > models.Hexaddr(s.ActiveEnd)
		}
}

func (s *Subnet) idxBounds(l, u net.IP) (index.Test, index.Test) {
	return func(o models.Model) bool {
			return o.Key() >= models.Hexaddr(l)
		},
		func(o models.Model) bool {
			return o.Key() > models.Hexaddr(u)
		}
}

// InSubnetRange returns true if the IP is inside the
// subnet CIDR.
func (s *Subnet) InSubnetRange(ip net.IP) bool {
	lower, upper := s.sBounds()
	hex := models.Hexaddr(ip)
	return lower(hex) && !upper(hex)
}

// InActiveRange returns true if the IP is inside the
// subnet's active range, inclusively.
func (s *Subnet) InActiveRange(ip net.IP) bool {
	lower, upper := s.aBounds()
	hex := models.Hexaddr(ip)
	return lower(hex) && !upper(hex)
}

// LeaseTimeFor returns the lease time for the IP in question.
// The value reflects if the IP in the active range,
// inside the subnet, or if the subnet is in proxy mode.
func (s *Subnet) LeaseTimeFor(ip net.IP) time.Duration {
	if s.Proxy {
		return 0
	} else if s.InActiveRange(ip) {
		return time.Duration(s.ActiveLeaseTime) * time.Second
	} else if s.InSubnetRange(ip) {
		return time.Duration(s.ReservedLeaseTime) * time.Second
	}
	return 0
}

// AsSubnet converts a models.Model into a *Subnet.
func AsSubnet(o models.Model) *Subnet {
	return o.(*Subnet)
}

// AsSubnets converts a list of models.Model into a list of *Subnet.
func AsSubnets(o []models.Model) []*Subnet {
	res := make([]*Subnet, len(o))
	for i := range o {
		res[i] = AsSubnet(o[i])
	}
	return res
}

// Validate ensures that the Subnet has valid values and
// do NOT overlap with out subnets.  This sets the available
// and valid flags.
func (s *Subnet) Validate() {
	s.Subnet.Fill()
	s.Subnet.Validate()
	_, subnet, err := net.ParseCIDR(s.Subnet.Subnet)
	if err != nil {
		s.Errorf("Invalid subnet %s: %v", s.Subnet.Subnet, err)
		return
	}
	validateIP4(s, subnet.IP)
	for _, p := range s.Pickers {
		_, ok := pickStrategies[p]
		if !ok {
			s.Errorf("Picker %s is not a valid lease picking strategy", p)
		}
	}
	if s.Pickers[0] == "point2point" {
		newOpts := []models.DhcpOption{}
		for i := range s.Options {
			switch dhcp.OptionCode(s.Options[i].Code) {
			case dhcp.OptionBroadcastAddress, dhcp.OptionSubnetMask:
				continue
			default:
				newOpts = append(newOpts, s.Options[i])
			}
		}
		mask := net.CIDRMask(31, 32)
		newOpts = append(newOpts, models.DhcpOption{
			Code:  byte(dhcp.OptionSubnetMask),
			Value: mask.String(),
		})
		s.Options = newOpts
	}
	// Build mask and broadcast for always
	mask := net.IP([]byte(net.IP(subnet.Mask).To4()))
	bcastBits := binary.BigEndian.Uint32(subnet.IP) | ^binary.BigEndian.Uint32(mask)
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, bcastBits)
	// Make sure that options have the correct netmask and broadcast options enabled
	needMask := true
	needBCast := true
	for i, opt := range s.Options {
		if opt.Code == byte(dhcp.OptionBroadcastAddress) {
			s.Options[i].Value = net.IP(buf).String()
			needBCast = false
		}
		if opt.Code == byte(dhcp.OptionSubnetMask) {
			s.Options[i].Value = mask.String()
			needMask = false
		}
	}
	if needMask {
		s.Options = append(s.Options, models.DhcpOption{byte(dhcp.OptionSubnetMask), mask.String()})
	}
	if needBCast {
		s.Options = append(s.Options, models.DhcpOption{byte(dhcp.OptionBroadcastAddress), net.IP(buf).String()})
	}
	s.AddError(index.CheckUnique(s, s.rt.stores("subnets").Items()))
	s.SetValid()
	if !s.Useable() {
		return
	}
	subnets := AsSubnets(s.rt.stores("subnets").Items())
	for i := range subnets {
		if subnets[i].Name == s.Name {
			continue
		}
		if subnets[i].subnet().Contains(s.subnet().IP) {
			s.Errorf("Overlaps subnet %s", subnets[i].Name)
		}
	}
	s.SetAvailable()
}

func (s *Subnet) BeforeDelete() error {
	e := &models.Error{Code: 409, Type: StillInUseError, Model: s.Prefix(), Key: s.Key()}
	for _, i := range s.rt.stores("reservations").Items() {
		res := AsReservation(i)
		if res.Scoped && s.InSubnetRange(res.Addr) {
			e.Errorf("Reservation %s is scoped for Subnet %s, cannot delete.", res.Addr.String(), s.Name)
		}
	}
	return e.HasError()
}

func (s *Subnet) OnChange(old store.KeySaver) error {
	oldSub := AsSubnet(old)
	if s.Strategy != oldSub.Strategy {
		s.Errorf("Strategy cannot change")
	}
	if s.Subnet.Subnet != oldSub.Subnet.Subnet {
		s.Errorf("Subnet range cannot change")
	}
	return s.MakeError(422, ValidationError, s)
}

// BeforeSave returns an error if the subnet is not valid.  This
// is used by the store system to avoid saving bad Subnets.
func (s *Subnet) BeforeSave() error {
	s.Validate()
	if !s.Useable() {
		return s.MakeError(422, ValidationError, s)
	}
	return nil
}

// OnLoad initializes and validates the Subnet when loading
// from a data store.
func (s *Subnet) OnLoad() error {
	defer func() { s.rt = nil }()
	s.Fill()
	return s.BeforeSave()
}

func (s *Subnet) next(used map[string]models.Model, token string, hint, via net.IP) (*Lease, bool) {
	for _, p := range s.Pickers {
		l, f := pickStrategies[p](s, used, token, hint, via)
		if !f {
			if l != nil {
				l.Via = via
			}
			return l, f
		}
	}
	return nil, false
}

var subnetLockMap = map[string][]string{
	"get":     {"subnets"},
	"create":  {"subnets:rw"},
	"update":  {"subnets:rw"},
	"patch":   {"subnets:rw"},
	"delete":  {"subnets:rw", "reservations"},
	"actions": {"subnets", "profiles", "params"},
}

// Locks will return a list of prefixes needed to lock for a specific action.
func (s *Subnet) Locks(action string) []string {
	return subnetLockMap[action]
}
