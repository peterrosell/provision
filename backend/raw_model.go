package backend

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/store"
	"github.com/xeipuuv/gojsonschema"
)

var (
	rawModelSchemaMap = map[string]interface{}{}
)

// RawModel models any data
type RawModel struct {
	*models.RawModel
	validate
}

func (r *RawModel) SetReadOnly(b bool) {
	(*r.RawModel)["ReadOnly"] = b
}

func (r *RawModel) SaveClean() store.KeySaver {
	mod := *r.RawModel
	mod.ClearValidation()
	return toBackend(&mod, r.rt)
}

func (r *RawModel) getStringValue(field string) string {
	if v, ok := (*r.RawModel)[field]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func (r *RawModel) getBooleanValue(field string) bool {
	if v, ok := (*r.RawModel)[field]; ok && v != nil {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func (r *RawModel) Indexes() map[string]index.Maker {
	fix := AsRawModel
	idxs := index.MakeBaseIndexes(r)
	sc, ok := rawModelSchemaMap[r.Prefix()].(map[string]interface{})
	if !ok {
		return idxs
	}

	m := sc["properties"].(map[string]interface{})
	for field, data := range m {
		schema := data.(map[string]interface{})
		t := schema["type"].(string)
		unique := false
		if v, ok := schema["isunique"]; ok {
			if b, ok := v.(bool); ok && b {
				unique = b
			}
		}

		var iii *index.Maker
		sfield := field

		switch t {
		case "string":
			ii := index.Make(
				unique,
				"string",
				func(i, j models.Model) bool { return fix(i).getStringValue(sfield) < fix(j).getStringValue(sfield) },
				func(ref models.Model) (gte, gt index.Test) {
					refField := fix(ref).getStringValue(sfield)
					return func(s models.Model) bool {
							return fix(s).getStringValue(sfield) >= refField
						},
						func(s models.Model) bool {
							return fix(s).getStringValue(sfield) > refField
						}
				},
				func(s string) (models.Model, error) {
					rm := fix(r.New())
					(*rm.RawModel)[sfield] = s
					return rm, nil
				})
			iii = &ii
		case "boolean":
			ii := index.MakeUnordered(
				"boolean",
				func(i, j models.Model) bool {
					return fix(i).getBooleanValue(sfield) == fix(j).getBooleanValue(sfield)
				},
				func(s string) (models.Model, error) {
					res := fix(r.New())
					switch s {
					case "true":
						(*res.RawModel)[sfield] = true
					case "false":
						(*res.RawModel)[sfield] = false
					default:
						return nil, errors.New("Runnable must be true or false")
					}
					return res, nil
				})
			iii = &ii
		}

		if iii != nil {
			idxs[sfield] = *iii
		}
	}

	return idxs
}

func (r *RawModel) New() store.KeySaver {
	res := &RawModel{RawModel: &models.RawModel{"Type": (*r.RawModel)["Type"].(string)}}
	if r.RawModel != nil && r.ChangeForced() {
		res.ForceChange()
	}
	res.rt = r.rt
	return res
}

func AsRawModel(o models.Model) *RawModel {
	return o.(*RawModel)
}

func AsRawModels(o []models.Model) []*RawModel {
	res := make([]*RawModel, len(o))
	for i := range o {
		res[i] = AsRawModel(o[i])
	}
	return res
}

func (r *RawModel) Validate() {
	idx := r.rt.stores((*r.RawModel)["Type"].(string)).Items()
	r.AddError(index.CheckUnique(r, idx))

	if schema, ok := rawModelSchemaMap[r.Prefix()]; ok {
		if schema != nil {
			validator, err := gojsonschema.NewSchema(gojsonschema.NewGoLoader(schema))
			if err != nil {
				r.AddError(err)
				return
			}
			res, err := validator.Validate(gojsonschema.NewGoLoader(r.RawModel))
			if err != nil {
				r.Errorf("Error validating value: %v", err)
			} else if !res.Valid() {
				for _, e := range res.Errors() {
					r.Errorf("Error in value: %v", e.String())
				}
			}
		}
	}

	if params, ok := (*r.RawModel)["Params"].(map[string]interface{}); ok {
		if pk, err := r.rt.PrivateKeyFor(r); err == nil {
			ValidateParams(r.rt, r, params, pk)
		} else {
			r.Errorf("Unable to get key: %v", err)
		}
	}

	r.SetValid()
	r.SetAvailable()
}

func (r *RawModel) BeforeSave() error {
	r.Validate()
	if !r.Useable() {
		return r.MakeError(422, ValidationError, r)
	}
	return nil
}

func (r *RawModel) OnLoad() error {
	defer func() { r.rt = nil }()
	r.Fill()
	return r.BeforeSave()
}

func (r *RawModel) Locks(action string) []string {
	return []string{(*r.RawModel)["Type"].(string) + ":rw", "profiles", "params"}
}

func (r *RawModel) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.RawModel)
}

func (r *RawModel) UnmarshalJSON(data []byte) error {
	ir := models.RawModel{}
	if err := json.Unmarshal(data, &ir); err != nil {
		return err
	}

	r.RawModel = &ir
	if (*r.RawModel)["Errors"] != nil {
		t := (*r.RawModel)["Errors"]
		n := []string{}
		if e := models.Remarshal(t, &n); e != nil {
			return e
		}
		(*r.RawModel)["Errors"] = n
	}
	return nil
}

func (r *RawModel) ParameterMaker(rt *RequestTracker, parameter string) (index.Maker, error) {
	fix := AsRawModel
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
			res := fix(r.New())
			p := map[string]interface{}{}
			p[parameter] = obj
			(*res.RawModel)["Params"] = p
			return res, nil
		}), nil

}
