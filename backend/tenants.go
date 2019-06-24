package backend

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/store"
)

// Tenant contains the runtime parameters for user manipulation
// around the models.Tenant object.
type Tenant struct {
	*models.Tenant
	validate
	cachedExpansion map[string]map[string]struct{}
	userAdd, userRm map[string]struct{}
}

// ExpandedMembers builds a cached map of members
// of this tenant by prefix.
func (t *Tenant) ExpandedMembers() map[string]map[string]struct{} {
	if t.cachedExpansion == nil {
		res := map[string]map[string]struct{}{}
		for k := range t.Members {
			res[k] = map[string]struct{}{}
			for idx := range t.Members[k] {
				res[k][t.Members[k][idx]] = struct{}{}
			}
		}
		t.cachedExpansion = res
	}
	return t.cachedExpansion
}

// SaveClean clears validation fields and returns a KeySaver
// object for use by the backing store.
func (t *Tenant) SaveClean() store.KeySaver {
	mod := *t.Tenant
	mod.ClearValidation()
	return ModelToBackend(&mod)
}

// AsTenant converts a models.Model into a *Tenant.
func AsTenant(t models.Model) *Tenant {
	return t.(*Tenant)
}

// AsTenants converts a list of models.Model into a list of *Tenant.
func AsTenants(o []models.Model) []*Tenant {
	res := make([]*Tenant, len(o))
	for i := range o {
		res[i] = AsTenant(o[i])
	}
	return res
}

// New returns a new empty Tenant with the RT field from the caller.
func (t *Tenant) New() store.KeySaver {
	res := &Tenant{Tenant: &models.Tenant{}}
	res.Fill()
	res.rt = t.rt
	return res
}

// Indexes returns the valid Indexes on Tenant.
func (t *Tenant) Indexes() map[string]index.Maker {
	fix := AsTenant
	res := index.MakeBaseIndexes(t)
	res["Name"] = index.Maker{
		Unique: true,
		Type:   "string",
		Less:   func(i, j models.Model) bool { return fix(i).Name < fix(j).Name },
		Eq:     func(i, j models.Model) bool { return fix(i).Name == fix(j).Name },
		Match:  func(i models.Model, re *regexp.Regexp) bool { return re.MatchString(fix(i).Name) },
		Tests: func(ref models.Model) (gte, gt index.Test) {
			name := fix(ref).Name
			return func(s models.Model) bool {
					return fix(s).Name >= name
				},
				func(s models.Model) bool {
					return fix(s).Name > name
				}
		},
		Fill: func(s string) (models.Model, error) {
			res := fix(t.New())
			res.Name = s
			return res, nil
		},
	}
	return res
}

var tenantLockMap = map[string][]string{
	"get":     {"tenants"},
	"create":  {"tenants:rw", "users:rw"},
	"update":  {"tenants:rw", "users:rw"},
	"delete":  {"users:rw", "tenants:rw"},
	"actions": {"tenants"},
}

// Locks returns a list of prefixes to lock for the specified action.
func (t *Tenant) Locks(action string) []string {
	return tenantLockMap[action]
}

// Validate makes sure the tenant is valid and available.
func (t *Tenant) Validate() {
	t.Tenant.Validate()
	t.AddError(index.CheckUnique(t, t.rt.stores("tenants").Items()))
	t.SetValid()
	t.SetAvailable()
}

// BeforeSave returns an error if the tenant is not Valid.  It is
// also responsible for validating User membership is valid.
// todo: Actually validate that all the items the Tenant references still exist.
func (t *Tenant) BeforeSave() error {
	t.Validate()
	if !t.Validated {
		return t.MakeError(422, ValidationError, t)
	}
	t.SetValid()
	if t.userAdd != nil && len(t.userAdd) > 0 {
		for _, name := range t.Users {
			if strings.Contains(name, ":") {
				continue
			}
			if t.rt.find("users", name) == nil {
				t.Errorf("User %s does not exist", name)
			}
		}
		uMap := map[string]string{}
		for _, un := range t.Users {
			uMap[un] = t.Name
		}
		for _, t2 := range t.rt.d("tenants").Items() {
			if t2.Key() == t.Key() {
				continue
			}
			tm := AsTenant(t2)
			for _, u2 := range tm.Users {
				if _, ok := uMap[u2]; ok {
					t.Errorf("User %s already in tenant %s, and users can only be in one tenant at a time",
						u2, tm.Name)
				}
			}
		}
	}
	t.SetAvailable()
	if !t.Available {
		return t.MakeError(422, ValidationError, t)
	}
	return nil
}

// AfterSave cleans up or sets the internal activeTenant fields
// on users.
func (t *Tenant) AfterSave() {
	t.cachedExpansion = nil
	if t.userRm != nil || t.userAdd != nil {
		for _, u2 := range t.rt.d("users").Items() {
			ru := AsUser(u2)
			if t.userRm != nil && len(t.userRm) > 0 {
				if _, ok := t.userRm[ru.Name]; ok {
					ru.activeTenant = ""
				}
				// If we have auth groups, check for tenant membership
				if gs, ok := ru.Meta["auth-groups"]; ok {
					parts := strings.Split(gs, ",")
					for _, g := range parts {
						group := fmt.Sprintf("auth-groups:%s", g)
						if _, ok := t.userRm[group]; ok {
							ru.activeTenant = ""
						}
					}
				}
			}
			if t.userAdd != nil && len(t.userAdd) > 0 {
				if _, ok := t.userAdd[ru.Name]; ok {
					ru.activeTenant = t.Name
				}
				// If we have auth groups, check for tenant membership
				if gs, ok := ru.Meta["auth-groups"]; ok {
					parts := strings.Split(gs, ",")
					for _, g := range parts {
						group := fmt.Sprintf("auth-groups:%s", g)
						if _, ok := t.userAdd[group]; ok {
							ru.activeTenant = t.Name
						}
					}
				}
			}
		}
	}
	t.userAdd, t.userRm = nil, nil
}

// OnLoad initializes the Tenant when loaded from the backing store.
func (t *Tenant) OnLoad() error {
	defer func() { t.rt = nil }()
	t.Fill()
	t.userAdd = map[string]struct{}{}
	for _, u := range t.Users {
		t.userAdd[u] = struct{}{}
	}
	if err := t.BeforeSave(); err != nil {
		return err
	}
	t.AfterSave()
	return nil
}

// OnCreate sets the internal add fields when a new object is created
// by the user.
func (t *Tenant) OnCreate() error {
	t.userAdd = map[string]struct{}{}
	for _, u := range t.Users {
		t.userAdd[u] = struct{}{}
	}
	return nil
}

// OnChange figures out which users need to be updates based
// upon being added or removed from this Tenant.
func (t *Tenant) OnChange(t2 store.KeySaver) error {
	t.userAdd, t.userRm = map[string]struct{}{}, map[string]struct{}{}
	oldT := AsTenant(t2)
	newU, oldU := map[string]struct{}{}, map[string]struct{}{}
	for _, u := range oldT.Users {
		oldU[u] = struct{}{}
	}
	for _, u := range t.Users {
		if _, ok := oldU[u]; !ok {
			t.userAdd[u] = struct{}{}
		}
		newU[u] = struct{}{}
	}
	for u := range oldU {
		if _, ok := newU[u]; !ok {
			t.userRm[u] = struct{}{}
		}
	}
	return nil
}

// BeforeDelete makes sure that the Tenant is empty of users before deleting the tenant.
func (t *Tenant) BeforeDelete() error {
	e := models.Error{Code: 409, Type: StillInUseError, Model: t.Prefix(), Key: t.Key()}
	if len(t.Users) != 0 {
		e.Errorf("Constraining Users: %v", t.Users)
	}
	return e.HasError()
}
