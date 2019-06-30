package backend

import (
	"regexp"
	"strings"
	"time"

	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/provision/store"
)

// User is an API user of DigitalRebar Provision
type User struct {
	*models.User
	validate
	activeTenant string
}

// SetReadOnly sets the ReadOnly flag (helper functino)
func (u *User) SetReadOnly(b bool) {
	u.ReadOnly = b
}

// Tenant returns the owning tenant for this user.
func (u *User) Tenant() string {
	return u.activeTenant
}

// SaveClean clears all validation information
// and returns the user as a KeySaver object
func (u *User) SaveClean() store.KeySaver {
	mod := *u.User
	mod.ClearValidation()
	return toBackend(&mod, u.rt)
}

// Indexes returns a map of indexes for the User model
func (u *User) Indexes() map[string]index.Maker {
	fix := AsUser
	res := index.MakeBaseIndexes(u)
	res["Name"] = index.Maker{
		Unique: true,
		Type:   "string",
		Less:   func(i, j models.Model) bool { return fix(i).Name < fix(j).Name },
		Eq:     func(i, j models.Model) bool { return fix(i).Name == fix(j).Name },
		Match:  func(i models.Model, re *regexp.Regexp) bool { return re.MatchString(fix(i).Name) },
		Tests: func(ref models.Model) (gte, gt index.Test) {
			refName := fix(ref).Name
			return func(s models.Model) bool {
					return fix(s).Name >= refName
				},
				func(s models.Model) bool {
					return fix(s).Name > refName
				}
		},
		Fill: func(s string) (models.Model, error) {
			u := fix(u.New())
			u.Name = s
			return u, nil
		},
	}
	return res
}

// New returns a new User object with
// the RT and forceChange flags from the
// calling object.
func (u *User) New() store.KeySaver {
	res := &User{User: &models.User{}}
	if u.User != nil && u.ChangeForced() {
		res.ForceChange()
	}
	res.rt = u.rt
	return res
}

// AsUser converts a models.Model to a User.
func AsUser(o models.Model) *User {
	return o.(*User)
}

// AsUsers converts a list of models.Model to
// a list of *User
func AsUsers(o []models.Model) []*User {
	res := make([]*User, len(o))
	for i := range o {
		res[i] = AsUser(o[i])
	}
	return res
}

// ChangePassword takes a clear text password, generates a hash,
// clears the previous secret, and saves the object in the store.
func (u *User) ChangePassword(rt *RequestTracker, newPass string) error {
	err := u.User.ChangePassword(newPass)
	if err == nil {
		_, err = rt.Save(u)
	}
	return err
}

// Validate makes sure that User is valid and available.
func (u *User) Validate() {
	u.User.Validate()
	u.AddError(index.CheckUnique(u, u.rt.stores("users").Items()))
	u.SetValid()
	for _, rName := range u.Roles {
		r := u.rt.find("roles", rName)
		if r == nil {
			u.Errorf("Role %s does not exist", rName)
		} else {
			role := AsRole(r)
			if !role.Available {
				u.Errorf("Role %s is not available", rName)
			}
		}
	}
	u.SetAvailable()
}

// GenClaim generates a *DrpCustomClaims structure from a grantor for a
// limited time with the desired roles.
func (u *User) GenClaim(grantor string, ttl time.Duration, wantedRoles ...string) *DrpCustomClaims {
	claim := NewClaim(u.Name, grantor, ttl)
	// Users always have the right to get a token and change their password.
	claim.AddRawClaim("users", "token,password,get", u.Name)
	claim.AddRawClaim("info", "get", "")
	if len(wantedRoles) == 0 {
		claim.AddRoles(u.Roles...)
		return claim
	}
	haveRoles := []*Role{}
	for _, r := range u.Roles {
		if robj := u.rt.find("roles", r); robj != nil {
			haveRoles = append(haveRoles, robj.(*Role))
		} else {
			u.rt.Errorf("User %s has missing role %s", u.Name, r)
		}
	}
	for i := range wantedRoles {
		r := strings.TrimSpace(wantedRoles[i])
		if robj := u.rt.find("roles", r); robj != nil {
			for _, test := range haveRoles {
				role := AsRole(robj)
				if test.Role.Contains(role.Role) {
					claim.AddRoles(r)
					break
				}
			}
		}
	}
	return claim
}

// BeforeSave validates and sets required fields
// on the User object before savining.
func (u *User) BeforeSave() error {
	if u.Secret == "" {
		u.Secret = models.RandString(16)
	}
	u.Validate()
	if !u.Useable() {
		return u.MakeError(422, ValidationError, u)
	}
	return nil
}

// AfterSave updates the tenant if needed
func (u *User) AfterSave() {
	u.updateTenant()
}

// OnLoad initializes and validates the user when loaded from
// the data store.
//
// The mustSave part was added to handle data migration from
// pre-Secret days to post-Secret days.  This could be removed
// once we feel that all deploys are past 3.6.0.
//
func (u *User) OnLoad() error {
	defer func() { u.rt = nil }()
	u.Fill()

	// This mustSave part is just to keep us from resaving all the users on startup.
	mustSave := false
	if u.Secret == "" {
		mustSave = true
	}
	err := u.BeforeSave()
	if err == nil && mustSave {
		v := u.SaveValidation()
		u.ClearValidation()
		err = u.rt.stores("users").backingStore.Save(u.Key(), u)
		u.RestoreValidation(v)
	}
	return err
}

// AfterDelete cleans up other objects after the data store
// has removed the User.
func (u *User) AfterDelete() {
	if u.activeTenant == "" {
		return
	}
	if obj := u.rt.find("tenants", u.activeTenant); obj != nil {
		t := AsTenant(obj)
		newUserList := []string{}
		for _, name := range t.Users {
			if name == u.Name {
				continue
			}
			newUserList = append(newUserList, name)
		}
		t.Users = newUserList
		u.rt.Save(t)
	}
}

func (u *User) updateTenant() error {
	for _, obj := range u.rt.stores("tenants").Items() {
		t := AsTenant(obj)
		for _, name := range t.Users {
			if strings.HasPrefix(name, "auth-groups:") {
				group := strings.TrimPrefix(name, "auth-groups:")
				if gs, ok := u.Meta["auth-groups"]; ok {
					parts := strings.Split(gs, ",")
					for _, g := range parts {
						if group == g {
							u.activeTenant = t.Name
							return nil
						}
					}
				}
			} else if name == u.Name {
				u.activeTenant = t.Name
				return nil
			}
		}
	}
	return nil
}

// OnCreate will lookup the tenants and see if one matches
func (u *User) OnCreate() error {
	return u.updateTenant()
}

var userLockMap = map[string][]string{
	"get":     {"users", "roles", "tenants", "params"},
	"create":  {"users:rw", "roles", "tenants:rw"},
	"update":  {"users:rw", "roles", "tenants:rw"},
	"patch":   {"users:rw", "roles", "tenants:rw"},
	"delete":  {"users:rw", "tenants:rw"},
	"actions": {"users", "roles", "profiles", "params"},
}

// Locks returns the object lock list for a given action for the User object
func (u *User) Locks(action string) []string {
	return userLockMap[action]
}
