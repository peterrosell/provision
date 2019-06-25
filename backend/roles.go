package backend

import (
	"regexp"

	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/provision/store"
)

// Role wraps the Role model to provide backend specific fields
// for tracking claims and validation.
type Role struct {
	*models.Role
	validate
	cachedClaims models.Claims
}

// SetReadOnly interface function to set the ReadOnly flag.
func (r *Role) SetReadOnly(b bool) {
	r.ReadOnly = b
}

// SaveClean interface function to clear Validation fields
// and return the object as a store.KeySaver for the data store.
func (r *Role) SaveClean() store.KeySaver {
	mod := *r.Role
	mod.ClearValidation()
	return ModelToBackend(&mod)
}

func (r *Role) ClearCachedClaims() {
	r.cachedClaims = nil
}

// CompiledClaims compiles and caches the claims for
// this role to accelerate lookups in the future.
func (r *Role) CompiledClaims() models.Claims {
	if r.cachedClaims == nil {
		r.cachedClaims = r.Role.Compile()
	}
	return r.cachedClaims
}

// AsRole converts a models.Model to a *Role.
func AsRole(r models.Model) *Role {
	return r.(*Role)
}

// AsRoles converts a list of models.Model to a list of *Role.
func AsRoles(o []models.Model) []*Role {
	res := make([]*Role, len(o))
	for i := range o {
		res[i] = AsRole(o[i])
	}
	return res
}

// New returns a new empty Role with the RT field
// from the calling function returned as a
// store.KeySaver for use by the data stores.
func (r *Role) New() store.KeySaver {
	res := &Role{Role: &models.Role{}}
	res.Fill()
	res.rt = r.rt
	return res
}

// Indexes returns a map of valid indexes for Role.
func (r *Role) Indexes() map[string]index.Maker {
	fix := AsRole
	res := index.MakeBaseIndexes(r)
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
			res := fix(r.New())
			res.Name = s
			return res, nil
		},
	}
	return res
}

var roleLockMap = map[string][]string{
	"get":     {"roles"},
	"create":  {"roles:rw"},
	"update":  {"roles:rw"},
	"patch":   {"roles:rw"},
	"delete":  {"users", "roles:rw"},
	"actions": {"roles"},
}

// Locks returns a list of prefixes needed to lock for the specific action.
func (r *Role) Locks(action string) []string {
	return roleLockMap[action]
}

// Validate ensures that the Role is valid and available.
// It sets those flags as appropriate.
func (r *Role) Validate() {
	r.Role.Validate()
	r.AddError(index.CheckUnique(r, r.rt.stores("roles").Items()))
	r.SetValid()
	r.SetAvailable()
}

// BeforeSave returns an error if the Role is not Valid.
// This aborts the save to a data store.
func (r *Role) BeforeSave() error {
	r.Validate()
	if !r.Validated {
		return r.MakeError(422, ValidationError, r)
	}
	return nil
}

// AfterSave clears the cachedClaims after a save operation.
func (r *Role) AfterSave() {
	r.cachedClaims = nil
}

// OnLoad initializes and validates the object as it is loaded from
// the data stores.
func (r *Role) OnLoad() error {
	defer func() { r.rt = nil }()
	r.Fill()
	return r.BeforeSave()
}

// BeforeDelete will abort the Delete operation if the Role is
// in use by a User.
func (r *Role) BeforeDelete() error {
	e := &models.Error{Code: 409, Type: StillInUseError, Model: r.Prefix(), Key: r.Key()}
	for _, u := range r.rt.d("users").Items() {
		user := AsUser(u)
		for _, name := range user.Roles {
			if name == r.Name {
				e.Errorf("In use by User %s", user.Name)
				break
			}
		}
	}
	return e.HasError()
}
