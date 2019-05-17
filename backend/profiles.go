package backend

import (
	"fmt"

	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/store"
)

// Profile represents a set of key/values to use in
// template expansion.
//
// There is one special profile named 'global' that acts
// as a global set of parameters for the system.
//
// These can be assigned to a machine's profile list.
type Profile struct {
	*models.Profile
	validate
}

func (p *Profile) SetReadOnly(b bool) {
	p.ReadOnly = b
}

func (p *Profile) SaveClean() store.KeySaver {
	mod := *p.Profile
	mod.ClearValidation()
	return toBackend(&mod, p.rt)
}

func (p *Profile) Indexes() map[string]index.Maker {
	fix := AsProfile
	res := index.MakeBaseIndexes(p)
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
		func(s string) (models.Model, error) {
			profile := fix(p.New())
			profile.Name = s
			return profile, nil
		})
	return res
}

func (p *Profile) ParameterMaker(rt *RequestTracker, parameter string) (index.Maker, error) {
	fix := AsProfile
	pobj := rt.find("params", parameter)
	if pobj == nil {
		return index.Maker{}, fmt.Errorf("Filter not found: %s", parameter)
	}
	param := AsParam(pobj)

	return index.Make(
		false,
		"parameter",
		func(i, j models.Model) bool {
			ip, _ := rt.GetParam(fix(i), parameter, true, false)
			jp, _ := rt.GetParam(fix(j), parameter, true, false)
			return GeneralLessThan(ip, jp)
		},
		func(ref models.Model) (gte, gt index.Test) {
			jp, _ := rt.GetParam(fix(ref), parameter, true, false)
			return func(s models.Model) bool {
					ip, _ := rt.GetParam(fix(s), parameter, true, false)
					return GeneralGreaterThanEqual(ip, jp)
				},
				func(s models.Model) bool {
					ip, _ := rt.GetParam(fix(s), parameter, true, false)
					return GeneralGreaterThan(ip, jp)
				}
		},
		func(s string) (models.Model, error) {
			obj, err := GeneralValidateParam(param, s)
			if err != nil {
				return nil, err
			}
			res := fix(p.New())
			res.Params = map[string]interface{}{}
			res.Params[parameter] = obj
			return res, nil
		}), nil

}

func (p *Profile) New() store.KeySaver {
	res := &Profile{Profile: &models.Profile{}}
	if p.Profile != nil && p.ChangeForced() {
		res.ForceChange()
	}
	res.Params = map[string]interface{}{}
	res.rt = p.rt
	return res
}

func (p *Profile) BeforeDelete() error {
	e := &models.Error{Code: 422, Type: ValidationError, Model: p.Prefix(), Key: p.Key()}
	if p.Name == p.rt.dt.GlobalProfileName {
		e.Errorf("Profile %s is the global profile, you cannot delete it", p.Name)
	}
	machines := p.rt.stores("machines")
	for _, i := range machines.Items() {
		m := AsMachine(i)
		if m.HasProfile(p.Name) {
			e.Errorf("Machine %s is using profile %s", m.UUID(), p.Name)
		}
	}
	stages := p.rt.stores("stages")
	for _, i := range stages.Items() {
		s := AsStage(i)
		if s.HasProfile(p.Name) {
			e.Errorf("Stage %s is using profile %s", s.Name, p.Name)
		}
	}
	return e.HasError()
}

func AsProfile(o models.Model) *Profile {
	return o.(*Profile)
}

func AsProfiles(o []models.Model) []*Profile {
	res := make([]*Profile, len(o))
	for i := range o {
		res[i] = AsProfile(o[i])
	}
	return res
}
func (p *Profile) Validate() {
	p.Profile.Validate()
	p.AddError(index.CheckUnique(p, p.rt.stores("profiles").Items()))
	if pk, err := p.rt.PrivateKeyFor(p); err == nil {
		ValidateParams(p.rt, p, p.Params, pk)
	} else {
		p.Errorf("Unable to get key: %v", err)
	}
	p.SetValid()
	p.SetAvailable()
}

func (p *Profile) BeforeSave() error {
	p.Validate()
	if !p.Useable() {
		return p.MakeError(422, ValidationError, p)
	}
	return nil
}

func (p *Profile) OnLoad() error {
	defer func() { p.rt = nil }()
	p.Fill()
	return p.BeforeSave()
}

func (p *Profile) AfterDelete() {
	p.rt.DeleteKeyFor(p)
}

var profileLockMap = map[string][]string{
	"get":     {"profiles", "params"},
	"create":  {"profiles:rw", "tasks", "params"},
	"update":  {"profiles:rw", "tasks", "params"},
	"patch":   {"profiles:rw", "tasks", "params"},
	"delete":  {"stages", "profiles:rw", "machines"},
	"actions": {"profiles", "params"},
}

func (p *Profile) Locks(action string) []string {
	return profileLockMap[action]
}
