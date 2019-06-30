package backend

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/provision/store"
)

// Plugin represents a single instance of a running plugin.
// This contains the configuration need to start this plugin instance.
type Plugin struct {
	*models.Plugin
	// If there are any errors in the start-up process, they will be
	// available here.
	// read only: true
	validate
}

func (n *Plugin) SetReadOnly(b bool) {
	n.ReadOnly = b
}

func (n *Plugin) SaveClean() store.KeySaver {
	mod := *n.Plugin
	mod.ClearValidation()
	return toBackend(&mod, n.rt)
}

func (n *Plugin) Indexes() map[string]index.Maker {
	fix := AsPlugin
	res := index.MakeBaseIndexes(n)
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
			plugin := fix(n.New())
			plugin.Name = s
			return plugin, nil
		},
	}
	res["Provider"] = index.Maker{
		Unique: false,
		Type:   "string",
		Less:   func(i, j models.Model) bool { return fix(i).Provider < fix(j).Provider },
		Eq:     func(i, j models.Model) bool { return fix(i).Provider == fix(j).Provider },
		Match:  func(i models.Model, re *regexp.Regexp) bool { return re.MatchString(fix(i).Provider) },
		Tests: func(ref models.Model) (gte, gt index.Test) {
			refProvider := fix(ref).Provider
			return func(s models.Model) bool {
					return fix(s).Provider >= refProvider
				},
				func(s models.Model) bool {
					return fix(s).Provider > refProvider
				}
		},
		Fill: func(s string) (models.Model, error) {
			plugin := fix(n.New())
			plugin.Provider = s
			return plugin, nil
		},
	}
	res["Params"] = index.MakeUnordered(
		"list",
		func(i, j models.Model) bool {
			p1 := fix(i).Params
			p2 := fix(j).Params
			probes := map[string]bool{}
			for k := range p2 {
				probes[k] = false
			}
			for k := range p1 {
				if v, ok := probes[k]; ok && !v {
					probes[k] = true
				}
			}
			for _, v := range probes {
				if !v {
					return false
				}
			}
			return true
		},
		func(s string) (models.Model, error) {
			res := fix(n.New())
			keys := strings.Split(s, ",")
			res.Params = map[string]interface{}{}
			for _, v := range keys {
				res.Params[strings.TrimSpace(v)] = struct{}{}
			}
			return res, nil
		})
	return res
}

func (n *Plugin) ParameterMaker(rt *RequestTracker, parameter string) (index.Maker, error) {
	fix := AsPlugin
	pobj := rt.find("params", parameter)
	if pobj == nil {
		return index.Maker{}, fmt.Errorf("Filter not found: %s", parameter)
	}
	param := AsParam(pobj)

	return index.Maker{
		Unique: false,
		Type:   "parameter",
		Less: func(i, j models.Model) bool {
			ip, _ := rt.GetParam(fix(i), parameter, true, false)
			jp, _ := rt.GetParam(fix(j), parameter, true, false)
			return GeneralLessThan(ip, jp)
		},
		Tests: func(ref models.Model) (gte, gt index.Test) {
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
		Fill: func(s string) (models.Model, error) {
			obj, err := GeneralValidateParam(param, s)
			if err != nil {
				return nil, err
			}
			res := fix(n.New())
			res.Params = map[string]interface{}{}
			res.Params[parameter] = obj
			return res, nil
		},
	}, nil

}

func (n *Plugin) Prefix() string {
	return "plugins"
}

func (n *Plugin) Key() string {
	return n.Name
}

func (n *Plugin) New() store.KeySaver {
	res := &Plugin{Plugin: &models.Plugin{}}
	if n.Plugin != nil && n.ChangeForced() {
		res.ForceChange()
	}
	res.rt = n.rt
	return res
}

func (n *Plugin) Validate() {
	n.Plugin.Validate()
	n.AddError(index.CheckUnique(n, n.rt.stores("plugins").Items()))
	if pk, err := n.rt.PrivateKeyFor(n); err == nil {
		ValidateParams(n.rt, n, n.Params, pk)
	} else {
		n.Errorf("Unable to get key: %v", err)
	}
	n.SetValid()
	n.SetAvailable()
}

func (n *Plugin) BeforeSave() error {
	n.Validate()
	if !n.Useable() {
		return n.MakeError(422, ValidationError, n)
	}
	return nil
}

func (n *Plugin) OnLoad() error {
	defer func() { n.rt = nil }()
	n.Fill()
	return n.BeforeSave()
}

func (n *Plugin) AfterDelete() {
	n.rt.DeleteKeyFor(n)
}

func AsPlugin(o models.Model) *Plugin {
	return o.(*Plugin)
}

func AsPlugins(o []models.Model) []*Plugin {
	res := make([]*Plugin, len(o))
	for i := range o {
		res[i] = AsPlugin(o[i])
	}
	return res
}

var pluginLockMap = map[string][]string{
	"get":     {"plugins", "params", "profiles"},
	"create":  {"plugins:rw", "params", "profiles"},
	"update":  {"plugins:rw", "params", "profiles"},
	"patch":   {"plugins:rw", "params", "profiles"},
	"delete":  {"plugins:rw", "params", "profiles"},
	"actions": {"plugins", "profiles", "params"},
}

func (n *Plugin) Locks(action string) []string {
	return pluginLockMap[action]
}
