package backend

import (
	"fmt"
	"net"
	"time"

	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
)

// LeaseNAK is the error that shall be returned when we cannot give a
// system the IP address it requested.  If FindLease or
// FindOrCreateLease return this as their error, then the DHCP
// midlayer must NAK the request.
type LeaseNAK error

func findViaReservation(rt *RequestTracker,
	strategy, token string,
	req net.IP, fake bool) (lease *Lease, reservation *Reservation, ok bool) {
	leases, reservations := rt.d("leases"), rt.d("reservations")
	for _, i := range reservations.Items() {
		reservation = AsReservation(i)
		if reservation.Token == token && reservation.Strategy == strategy {
			break
		}
		reservation = nil
	}
	if reservation == nil {
		return
	}
	if fake {
		return nil, reservation, true
	}
	// We found a reservation for this strategy/token
	// combination, see if we can create a lease using it.
	ok = false
	if found := leases.Find(reservation.Key()); found != nil {
		ok = true
		// We found a lease for this IP.
		lease = AsLease(found)
		if lease.Token == reservation.Token &&
			lease.Strategy == reservation.Strategy {
			// This is our lease.  Renew it.
			rt.Switch("dhcp").Infof("Reservation for %s has a lease, using it.", lease.Addr.String())
			return
		}
		if lease.Expired() {
			// The lease has expired.  Take it over
			rt.Switch("dhcp").Infof("Reservation for %s is taking over an expired lease", lease.Addr.String())
			lease.Token = token
			lease.Strategy = strategy
			return
		}
		// The lease has not expired, and it is not ours.
		// We have no choice but to fall through to subnet code until
		// the current lease has expired.
		rt.Switch("dhcp").Infof("Reservation %s (%s:%s): A lease exists for that address, has been handed out to %s:%s",
			reservation.Addr,
			reservation.Strategy,
			reservation.Token,
			lease.Strategy,
			lease.Token)
		lease = nil
		return
	}
	// We did not find a lease for this IP, and findLease has already guaranteed that
	// either there is no lease for this token or that the old lease has been NAK'ed.
	// We are free to create a new lease for this Reservation.
	lease = &Lease{}
	Fill(lease)
	lease.Addr = reservation.Addr
	lease.Strategy = reservation.Strategy
	lease.Token = reservation.Token
	lease.State = "OFFER"
	return
}

func findLease(rt *RequestTracker, strategy, token string, req net.IP) (lease *Lease, err error) {
	reservations, leases := rt.d("reservations"), rt.d("leases")
	hexreq := models.Hexaddr(req.To4())
	found := leases.Find(hexreq)
	if found == nil {
		return
	}
	// Found a lease that exists for the requested address.
	lease = AsLease(found)
	if !lease.Expired() && (lease.Token != token || lease.Strategy != strategy) {
		// And it belongs to someone else.  So sad, gotta NAK
		err = LeaseNAK(fmt.Errorf("Lease for %s owned by %s:%s",
			hexreq, lease.Strategy, lease.Token))
		lease = nil
		return
	}
	_, reservation, _ := findViaReservation(rt, strategy, token, req, true)
	if reservation == nil {
		// This is the lease we want, but if there is a conflicting reservation we
		// may force the client to give it up.
		if rfound := reservations.Find(lease.Key()); rfound != nil {
			reservation = AsReservation(rfound)
			if reservation.Strategy != lease.Strategy ||
				reservation.Token != lease.Token {
				lease.Invalidate()
				rt.Save(lease)
				err = LeaseNAK(fmt.Errorf("Reservation %s (%s:%s) conflicts with %s:%s",
					reservation.Addr,
					reservation.Strategy,
					reservation.Token,
					lease.Strategy,
					lease.Token))
				lease = nil
				return
			}
		}
	} else if !reservation.Addr.Equal(lease.Addr) {
		// Someone reserved a different IP address for us.  The client needs to give up
		// current lease
		lease.Invalidate()
		rt.Save(lease)
		err = LeaseNAK(fmt.Errorf("Reservation %s (%s:%s) changed our address from %s",
			reservation.Addr,
			reservation.Strategy,
			reservation.Token,
			lease.Addr))
		lease = nil
		return
	}
	lease.Strategy = strategy
	lease.Token = token
	lease.ExpireTime = time.Now().Add(2 * time.Second)
	rt.Switch("dhcp").Infof("Found our lease for strategy: %s token %s, will use it", strategy, token)
	return
}

// FindLease finds an appropriate matching Lease.
// If a non-nil error is returned, the DHCP system must NAK the response.
// If lease and error are nil, the DHCP system must not respond to the request.
// Otherwise, the lease will be returned with its ExpireTime updated and the Lease saved.
//
// This function should be called in response to a DHCPREQUEST.
func FindLease(rt *RequestTracker,
	strategy, token string,
	req net.IP) (lease *Lease, subnet *Subnet, reservation *Reservation, err error) {
	rt.Do(func(d Stores) {
		lease, err = findLease(rt, strategy, token, req)
		if err != nil {
			return
		}
		if lease == nil {
			fake := &Lease{Lease: &models.Lease{Addr: req}}
			reservation = fake.Reservation(rt)
			subnet = fake.Subnet(rt)
			if reservation != nil {
				err = LeaseNAK(fmt.Errorf("No lease for %s, convered by reservation %s", req, reservation.Addr))
			}
			if subnet != nil {
				err = LeaseNAK(fmt.Errorf("No lease for %s, covered by subnet %s", req, subnet.subnet().IP))
			}
			return
		}
		subnet = lease.Subnet(rt)
		reservation = lease.Reservation(rt)
		if reservation == nil && subnet == nil {
			rt.Remove(lease)
			err = LeaseNAK(fmt.Errorf("Lease %s has no reservation or subnet, it is dead to us.", lease.Addr))
			return
		}
		if reservation != nil {
			lease.ExpireTime = time.Now().Add(2 * time.Hour)
		}
		if subnet != nil {
			lease.ExpireTime = time.Now().Add(subnet.LeaseTimeFor(lease.Addr))
			if !subnet.Enabled && reservation == nil {
				// We aren't enabled, so act like we are silent.
				lease = nil
				return
			}
		}
		lease.State = "ACK"
		rt.Save(lease)
	})
	return
}

func findViaSubnet(rt *RequestTracker,
	strategy, token string,
	req net.IP,
	vias []net.IP,
	fake bool) (lease *Lease, subnet *Subnet, fresh bool) {
	leases, subnets, reservations := rt.d("leases"), rt.d("subnets"), rt.d("reservations")
	for _, idx := range subnets.Items() {
		candidate := AsSubnet(idx)
		for _, via := range vias {
			if via == nil || !via.IsGlobalUnicast() {
				continue
			}
			if candidate.subnet().Contains(via) && candidate.Strategy == strategy {
				subnet = candidate
				break
			}
		}
	}
	if subnet == nil {
		// There is no subnet that can handle the vias we want
		return
	}
	if !subnet.Enabled {
		// Subnet isn't enabled, don't give out leases.
		return
	}
	// Return a fake lease
	if subnet.Proxy || fake {
		lease = &Lease{}
		Fill(lease)
		lease.Strategy = strategy
		lease.Token = token
		lease.State = "FAKE"
		return lease, subnet, true
	}
	currLeases, _ := index.Between(
		models.Hexaddr(subnet.ActiveStart),
		models.Hexaddr(subnet.ActiveEnd))(&leases.Index)
	currReservations, _ := index.Between(
		models.Hexaddr(subnet.ActiveStart),
		models.Hexaddr(subnet.ActiveEnd))(&reservations.Index)
	usedAddrs := map[string]models.Model{}
	for _, i := range currLeases.Items() {
		currLease := AsLease(i)
		// While we are iterating over leases, see if we run across a candidate.
		if (req == nil || req.IsUnspecified() || currLease.Addr.Equal(req)) &&
			currLease.Strategy == strategy && currLease.Token == token {
			lease = currLease
		}
		// Leases get a false in the map.
		usedAddrs[currLease.Key()] = currLease
	}
	for _, i := range currReservations.Items() {
		// While we are iterating over reservations, see if any candidate we found is still kosher.
		currRes := AsReservation(i)
		if lease != nil &&
			currRes.Strategy == strategy &&
			currRes.Token == token {
			// If we have a matching reservation and we found a similar candidate,
			// then the candidate cannot possibly be a lease we should use,
			// because it would have been refreshed by the lease code.
			lease = nil
		}
		// Reservations get true
		usedAddrs[currRes.Key()] = currRes
	}
	if lease != nil {
		rt.Switch("dhcp").Infof("Subnet %s: handing out existing lease for %s to %s:%s", subnet.Name, lease.Addr, strategy, token)
		return
	}
	rt.Switch("dhcp").Infof("Subnet %s: %s:%s is in my range, attempting lease creation.", subnet.Name, strategy, token)
	lease, _ = subnet.next(usedAddrs, token, req)
	if lease != nil {
		lease.State = "PROBE"
		if leases.Find(lease.Key()) == nil {
			leases.Add(lease)
		}
		fresh = true
		return
	}
	rt.Switch("dhcp").Infof("Subnet %s: No lease for %s:%s, it gets no IP from us", subnet.Name, strategy, token)
	return nil, nil, false
}

// FakeLeaseFor returns a lease that has zero duration and that should not be saved.
// It is intended for use when we are acting as a proxy DHCP server or we are acting
// as a BINL server.
func FakeLeaseFor(rt *RequestTracker,
	strategy, token string,
	via []net.IP) (lease *Lease, subnet *Subnet, reservation *Reservation) {
	rt.Do(func(d Stores) {
		_, reservation, _ = findViaReservation(rt, strategy, token, nil, true)
		lease, subnet, _ = findViaSubnet(rt, strategy, token, nil, via, true)
	})
	return
}

// FindOrCreateLease will return a lease for the passed information, creating it if it can.
// If a non-nil Lease is returned, it has been saved and the DHCP system can offer it.
// If the returned lease is nil, then the DHCP system should not respond.
//
// This function should be called for DHCPDISCOVER.
func FindOrCreateLease(rt *RequestTracker,
	strategy, token string,
	req net.IP,
	via []net.IP) (lease *Lease, subnet *Subnet, reservation *Reservation, fresh bool) {
	rt.Do(func(d Stores) {
		leases := d("leases")
		var ok bool
		lease, reservation, ok = findViaReservation(rt, strategy, token, req, false)
		if lease == nil {
			lease, subnet, fresh = findViaSubnet(rt, strategy, token, req, via, false)
		} else {
			subnet = lease.Subnet(rt)
		}
		if lease != nil {
			// Clean up any other leases that have this strategy and token lying around.
			toRemove := []models.Model{}
			for _, dup := range leases.Items() {
				candidate := AsLease(dup)
				if candidate.Strategy == strategy &&
					candidate.Token == token &&
					!candidate.Addr.Equal(lease.Addr) {
					toRemove = append(toRemove, candidate)
				}
			}
			leases.Remove(toRemove...)

			// If ViaReservation created it, then add it
			if !ok && (subnet == nil || !subnet.Proxy) {
				leases.Add(lease)
			}
			lease.ExpireTime = time.Now().Add(time.Minute)

			// If we are proxy, we don't save leases.  The address is empty.
			if subnet == nil || !subnet.Proxy {
				rt.Save(lease)
			}
		}
	})
	return
}
