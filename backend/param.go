package backend

import (
	"errors"

	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/store"
	"github.com/xeipuuv/gojsonschema"
)

type Paramer interface {
	models.Model
	GetParams(Stores, bool) map[string]interface{}
	SetParams(Stores, map[string]interface{}) error
	GetParam(Stores, string, bool) (interface{}, bool)
	SetParam(Stores, string, interface{}) error
}

// Param represents metadata about a Parameter or a Preference.
// Specifically, it contains a description of what the information
// is for, detailed documentation about the param, and a JSON schema that
// the param must match to be considered valid.
type Param struct {
	*models.Param
	validate
	validator *gojsonschema.Schema
}

func (p *Param) SetReadOnly(b bool) {
	p.ReadOnly = b
}

func (p *Param) SaveClean() store.KeySaver {
	mod := *p.Param
	mod.ClearValidation()
	return toBackend(&mod, p.rt)
}

func AsParam(o models.Model) *Param {
	return o.(*Param)
}

func AsParams(o []models.Model) []*Param {
	res := make([]*Param, len(o))
	for i := range o {
		res[i] = AsParam(o[i])
	}
	return res
}

func (p *Param) New() store.KeySaver {
	res := &Param{Param: &models.Param{}}
	if p.Param != nil && p.ChangeForced() {
		res.ForceChange()
	}
	res.rt = p.rt
	return res
}

func (p *Param) Indexes() map[string]index.Maker {
	fix := AsParam
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
			param := fix(p.New())
			param.Name = s
			return param, nil
		})
	res["Secure"] = index.Make(
		false,
		"boolean",
		func(i, j models.Model) bool {
			return (!fix(i).Secure) && fix(j).Secure
		},
		func(ref models.Model) (gte, gt index.Test) {
			avail := fix(ref).Secure
			return func(s models.Model) bool {
					v := fix(s).Secure
					return v || (v == avail)
				},
				func(s models.Model) bool {
					return fix(s).Secure && !avail
				}
		},
		func(s string) (models.Model, error) {
			res := fix(p.New())
			switch s {
			case "true":
				res.Secure = true
			case "false":
				res.Secure = false
			default:
				return nil, errors.New("Secure must be true or false")
			}
			return res, nil
		})
	return res
}

func (p *Param) Validate() {
	p.Param.Validate()
	p.SetValid()
	p.SetAvailable()
}

func (p *Param) BeforeSave() error {
	p.Validate()
	if !p.Useable() {
		return p.MakeError(422, ValidationError, p)
	}
	return nil
	// Arguably, we should also detect when an attempted schema update happens
	// and verify that it does not break validation, or at least report on what
	// previously-valid values would become invalid.
	// However, I don't feel like writing that code for now, so ignore the problem.
}

func (p *Param) OnLoad() error {
	defer func() { p.rt = nil }()
	p.Fill()
	return p.BeforeSave()
}

func validateAgainstSchema(val interface{}, schema *gojsonschema.Schema) error {
	res, err := schema.Validate(gojsonschema.NewGoLoader(val))
	if err != nil {
		return err
	}
	if res.Valid() {
		return nil
	}
	e := &models.Error{}
	for _, i := range res.Errors() {
		e.Errorf(i.String())
	}
	return e
}

func (p *Param) ValidateValue(val interface{}, key []byte) error {
	if !p.Useable() {
		return p.MakeError(422, ValidationError, p)
	}
	rv := val
	if p.Secure {
		sd := &models.SecureData{}
		if err := models.Remarshal(val, sd); err != nil {
			return err
		}
		if err := sd.Validate(); err != nil {
			return err
		}
		var realVal interface{}
		if err := sd.Unmarshal(key, &realVal); err != nil {
			return err
		}
		rv = realVal
	}
	if p.Schema == nil {
		return nil
	}
	if p.validator == nil {
		p.validator, _ = gojsonschema.NewSchema(gojsonschema.NewGoLoader(p.Schema))
	}
	res, err := p.validator.Validate(gojsonschema.NewGoLoader(rv))
	if err != nil {
		return err
	}
	if res.Valid() {
		return nil
	}
	e := &models.Error{}
	for _, i := range res.Errors() {
		e.Errorf(i.String())
	}
	return e
}

func ValidateParams(rt *RequestTracker, e models.ErrorAdder, params map[string]interface{}, key []byte) {
	for k, v := range params {
		if pIdx := rt.find("params", k); pIdx != nil {
			param := AsParam(pIdx)
			if err := param.ValidateValue(v, key); err != nil {
				e.Errorf("Key '%s': invalid val '%v': %v", k, v, err)
			}
		}
	}
}

var paramLockMap = map[string][]string{
	"get":     {"params"},
	"create":  {"params", "profiles"},
	"update":  {"params", "profiles"},
	"patch":   {"params", "profiles"},
	"delete":  {"params", "profiles"},
	"actions": {"params", "profiles"},
}

func (p *Param) Locks(action string) []string {
	return paramLockMap[action]
}
