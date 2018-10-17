package backend

import (
	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/store"
)

// RawModel models any data
type RawModel struct {
	*models.RawModel
	validate
}

func (r *RawModel) SetReadOnly(b bool) {
	r.ReadOnly = b
}

func (r *RawModel) SaveClean() store.KeySaver {
	mod := *r.RawModel
	mod.ClearValidation()
	return toBackend(&mod, r.rt)
}

func (r *RawModel) Indexes() map[string]index.Maker {
	res := index.MakeBaseIndexes(r)
	/*
		fix := AsRawModel
		res["Addr"] = index.Make(
			false,
			"IP Address",
			func(i, j models.Model) bool {
				n, o := big.Int{}, big.Int{}
				n.SetBytes(fix(i).Addr.To16())
				o.SetBytes(fix(j).Addr.To16())
				return n.Cmp(&o) == -1
			},
			func(ref models.Model) (gte, gt index.Test) {
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
			func(s string) (models.Model, error) {
				ip := net.ParseIP(s)
				if ip == nil {
					return nil, errors.New("Addr must be an IP address")
				}
				lease := fix(l.New())
				lease.Addr = ip
				return lease, nil
			})
		res["Token"] = index.Make(
			false,
			"string",
			func(i, j models.Model) bool { return fix(i).Token < fix(j).Token },
			func(ref models.Model) (gte, gt index.Test) {
				token := fix(ref).Token
				return func(s models.Model) bool {
						return fix(s).Token >= token
					},
					func(s models.Model) bool {
						return fix(s).Token > token
					}
			},
			func(s string) (models.Model, error) {
				lease := fix(l.New())
				lease.Token = s
				return lease, nil
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
			func(s string) (models.Model, error) {
				lease := fix(l.New())
				lease.Strategy = s
				return lease, nil
			})
		res["State"] = index.Make(
			false,
			"string",
			func(i, j models.Model) bool { return fix(i).State < fix(j).State },
			func(ref models.Model) (gte, gt index.Test) {
				strategy := fix(ref).State
				return func(s models.Model) bool {
						return fix(s).State >= strategy
					},
					func(s models.Model) bool {
						return fix(s).State > strategy
					}
			},
			func(s string) (models.Model, error) {
				lease := fix(l.New())
				lease.State = s
				return lease, nil
			})
		res["ExpireTime"] = index.Make(
			false,
			"Date/Time string",
			func(i, j models.Model) bool { return fix(i).ExpireTime.Before(fix(j).ExpireTime) },
			func(ref models.Model) (gte, gt index.Test) {
				expireTime := fix(ref).ExpireTime
				return func(s models.Model) bool {
						ttime := fix(s).ExpireTime
						return ttime.Equal(expireTime) || ttime.After(expireTime)
					},
					func(s models.Model) bool {
						return fix(s).ExpireTime.After(expireTime)
					}
			},
			func(s string) (models.Model, error) {
				t := &time.Time{}
				if err := t.UnmarshalText([]byte(s)); err != nil {
					return nil, fmt.Errorf("ExpireTime is not valid: %v", err)
				}
				lease := fix(l.New())
				lease.ExpireTime = *t
				return lease, nil
			})
	*/
	return res
}

func (r *RawModel) New() store.KeySaver {
	res := &RawModel{RawModel: &models.RawModel{Type: r.Type}}
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
	idx := r.rt.stores(r.Type).Items()
	r.AddError(index.CheckUnique(r, idx))
	r.SetValid()
	r.SetAvailable()
}

func (r *RawModel) Locks(action string) []string {
	return []string{r.Type}
}
