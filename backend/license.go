package backend

import (
	"encoding/base64"
	"time"

	utils2 "github.com/VictorLowther/jsonpatch2/utils"
	"github.com/digitalrebar/provision/models"
	"golang.org/x/crypto/nacl/sign"
)

// Contains license validation code.

var publicKeysBase64 = []string{"iTeYR10TfD+dHBCl/+2u2T6WfVoGzLIyOk5850jQqQM="}

// AllLicenses returns the current expiry state of the current
// licenses and caches that result.
func (dt *DataTracker) AllLicenses() models.LicenseBundle {
	res := dt.licenses
	if res.Licenses == nil {
		return res
	}
	now := time.Now()
	res.Licenses = []models.License{}
	for _, l := range dt.licenses.Licenses {
		l.Active, l.Expired = l.Check(now)
		res.Licenses = append(res.Licenses, l)
	}
	return res
}

// LicenseFor returns the expiry state of the specified component.
func (dt *DataTracker) LicenseFor(component string) *models.License {
	if dt.licenses.Licenses == nil {
		return nil
	}

	// Check for "carte-blanche" license and return it if active.
	for _, l := range dt.licenses.Licenses {
		if l.Name == "carte-blanche" {
			l.Active, l.Expired = l.Check(time.Now())
			if l.Active {
				return &l
			}
			break
		}
	}

	// Check for "upto-nodes"
	for _, l := range dt.licenses.Licenses {
		if l.Name == "upto-nodes" {
			l.Active, l.Expired = l.Check(time.Now())
			if l.Active {
				// Marshal data into map of string / int counts
				var counts map[string]int
				if err := utils2.Remarshal(l.Data, &counts); err != nil {
					return nil
				}
				for ty, count := range counts {
					rt := dt.Request(dt, ty)
					objCount := 0
					rt.Do(func(d Stores) {
						objs := d(ty)
						objCount = objs.Count()
					})
					if objCount > count {
						return nil
					}
				}
				return &l
			}
			break
		}
	}

	// Look for the specific license.
	for _, l := range dt.licenses.Licenses {
		if l.Name == component {
			l.Active, l.Expired = l.Check(time.Now())
			return &l
		}
	}
	return nil
}

func (dt *DataTracker) loadLicense(rt *RequestTracker) {
	dt.licenses = models.LicenseBundle{Licenses: []models.License{}}
	p := rt.find("profiles", "rackn-license")
	if p == nil {
		rt.Infof("Missing rackn-license profile, no enterprise functionality will be enabled")
		rt.Infof("Contact support@rackn.com to enable enterprise functionality.")
		return
	}
	licenseProfile := AsProfile(p)

	d, ok := licenseProfile.Params["rackn/license"].(string)
	if !ok {
		rt.Errorf("Failed to find rackn/license in the rackn-license profile, your license is malformed")
		rt.Errorf("Contact support@rackn.com for an updated license")
		return
	}
	signedMessage, err := base64.StdEncoding.DecodeString(d)
	if err != nil {
		rt.Errorf("Failed to decode license information, your license is malformed")
		rt.Errorf("Contact support@rackn.com for an updated license")
		return
	}
	validLicense := false
	for _, p64k := range publicKeysBase64 {
		pubkey, _ := base64.StdEncoding.DecodeString(p64k)
		var pk [32]byte
		copy(pk[:], pubkey)
		buf, ok := sign.Open([]byte{}, signedMessage, &pk)
		if !ok {
			continue
		}
		if err := models.DecodeYaml(buf, &dt.licenses); err != nil {
			rt.Errorf("Failed to unmarshal license information, your license is malformed")
			rt.Errorf("Contact support@rackn.com for an updated license")
			dt.licenses = models.LicenseBundle{}
			return
		}
		validLicense = true
		break
	}
	if !validLicense {
		rt.Errorf("License not properly signed.")
		rt.Errorf("Contact support@rackn.com for an updated license")
		return
	}

	// Validate endpoint list presence
	hasOne := false
	found := false
	for _, e := range dt.licenses.Endpoints {
		hasOne = true
		if e == "MatchAny" {
			found = true
			break
		}
		if e == dt.DrpId {
			found = true
			break
		}
	}
	if hasOne && !found {
		rt.Errorf("License contains Endpoints and this one (%s) is not listed.", dt.DrpId)
		rt.Errorf("Contact support@rackn.com for an updated license")
		return
	}

	now := time.Now()
	for i := range dt.licenses.Licenses {
		dt.licenses.Licenses[i].Check(now)
	}
	rt.Infof("Licenses loaded")
}
