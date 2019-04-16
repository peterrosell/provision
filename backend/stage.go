package backend

import (
	"errors"
	"fmt"
	"sync"
	"text/template"

	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/store"
)

// Stage encapsulates tasks we want to run a machine
type Stage struct {
	*models.Stage
	validate
	renderers    renderers
	rootTemplate *template.Template
	tmplMux      sync.Mutex
}

// SetReadOnly interface function to set the ReadOnly flag.
func (s *Stage) SetReadOnly(b bool) {
	s.ReadOnly = b
}

// SaveClean interface function to clear validation fields
// and return a store.KeySaver for use in data stores.
func (s *Stage) SaveClean() store.KeySaver {
	mod := *s.Stage
	mod.ClearValidation()
	return toBackend(&mod, s.rt)
}

// HasTask returns true if the task name is in the Tasks list.
func (s *Stage) HasTask(ts string) bool {
	for _, p := range s.Tasks {
		if p == ts {
			return true
		}
	}
	return false
}

// HasProfile returns true if the profile name is in the Profiles list.
func (s *Stage) HasProfile(name string) bool {
	for _, e := range s.Profiles {
		if e == name {
			return true
		}
	}
	return false
}

// Indexes returns a map of valid indexes for Stage.
func (s *Stage) Indexes() map[string]index.Maker {
	fix := AsStage
	res := index.MakeBaseIndexes(s)
	res["Name"] = index.Make(
		true,
		"string",
		func(i, j models.Model) bool {
			return fix(i).Name < fix(j).Name
		},
		func(ref models.Model) (gte, gt index.Test) {
			name := fix(ref).Name
			return func(ss models.Model) bool {
					return fix(ss).Name >= name
				},
				func(ss models.Model) bool {
					return fix(ss).Name > name
				}
		},
		func(ss string) (models.Model, error) {
			res := fix(s.New())
			res.Name = ss
			return res, nil
		})
	res["BootEnv"] = index.Make(
		false,
		"string",
		func(i, j models.Model) bool {
			return fix(i).BootEnv < fix(j).BootEnv
		},
		func(ref models.Model) (gte, gt index.Test) {
			bootenv := fix(ref).BootEnv
			return func(ss models.Model) bool {
					return fix(ss).BootEnv >= bootenv
				},
				func(ss models.Model) bool {
					return fix(ss).BootEnv > bootenv
				}
		},
		func(ss string) (models.Model, error) {
			res := fix(s.New())
			res.BootEnv = ss
			return res, nil
		})
	res["Reboot"] = index.Make(
		false,
		"boolean",
		func(i, j models.Model) bool {
			return !fix(i).Reboot && fix(j).Reboot
		},
		func(ref models.Model) (gte, gt index.Test) {
			reboot := fix(ref).Reboot
			return func(s models.Model) bool {
					v := fix(s).Reboot
					return v || (v == reboot)
				},
				func(s models.Model) bool {
					return fix(s).Reboot && !reboot
				}
		},
		func(ss string) (models.Model, error) {
			res := fix(s.New())
			switch ss {
			case "true":
				res.Reboot = true
			case "false":
				res.Reboot = false
			default:
				return nil, errors.New("Reboot must be true or false")
			}
			return res, nil
		})
	return res
}

func (s *Stage) genRoot(commonRoot *template.Template, e models.ErrorAdder) *template.Template {
	res := models.MergeTemplates(commonRoot, s.Templates, e)
	for i, tmpl := range s.Templates {
		if tmpl.Path == "" {
			e.Errorf("Template[%d] needs a Path", i)
		}
	}
	if s.HasError() != nil {
		return nil
	}
	return res
}

func (s *Stage) ParameterMaker(rt *RequestTracker, parameter string) (index.Maker, error) {
	fix := AsStage
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
			return func(si models.Model) bool {
					ip, _ := rt.GetParam(fix(si), parameter, true, false)
					return GeneralGreaterThanEqual(ip, jp)
				},
				func(si models.Model) bool {
					ip, _ := rt.GetParam(fix(si), parameter, true, false)
					return GeneralGreaterThan(ip, jp)
				}
		},
		func(str string) (models.Model, error) {
			obj, err := GeneralValidateParam(param, str)
			if err != nil {
				return nil, err
			}
			res := fix(s.New())
			res.Params = map[string]interface{}{}
			res.Params[parameter] = obj
			return res, nil
		}), nil

}

// Validate ensures that the Stage is valid and available.
// Setting those flags as appropriate.  Profiles, Tasks,
// and BootEnv are validate for presence.  Renderers are
// updated as appropriate.
func (s *Stage) Validate() {
	s.Stage.Validate()
	for idx, ti := range s.Templates {
		ti.SanityCheck(idx, s, false)
	}
	s.AddError(index.CheckUnique(s, s.rt.stores("stages").Items()))
	if pk, err := s.rt.PrivateKeyFor(s); err == nil {
		ValidateParams(s.rt, s, s.Params, pk)
	} else {
		s.Errorf("Unable to get key: %v", err)
	}
	if !s.SetValid() {
		// If we have not been validated at this point, return.
		return
	}
	// With FSM Runner - Runner always Waits - to begin deprecation process
	// we will always mark the stage as RunnerWait true
	s.RunnerWait = true
	// We are syntactically valid, although we may not be useable.
	s.renderers = renderers{}
	// First, the stuff that must be correct in order for
	for _, taskName := range s.Tasks {
		if s.rt.find("tasks", taskName) == nil {
			s.Errorf("Task %s does not exist", taskName)
		}
	}
	for _, profileName := range s.Profiles {
		if s.rt.find("profiles", profileName) == nil {
			s.Errorf("Profile %s does not exist", profileName)
		}
	}
	if s.BootEnv != "" {
		s.rt.Tracef("Stage %s: Looking for bootenv %s", s.Name, s.BootEnv)
		if nbFound := s.rt.find("bootenvs", s.BootEnv); nbFound == nil {
			s.rt.Errorf("Stage %s: Cannot validate bootenv %s, does not exist", s.Name, s.BootEnv)
			s.Errorf("BootEnv %s does not exist", s.BootEnv)
		} else {
			env := AsBootEnv(nbFound)
			if !env.Available {
				s.Errorf("Stage %s wants BootEnv %s, which is not available", s.Name, s.BootEnv)
			} else {
				for _, ti := range env.Templates {
					for _, si := range s.Templates {
						if si.Path == ti.Path {
							s.Errorf("Stage %s Template %s overlaps with BootEnv %s Template %s",
								s.Name, si.Name, s.BootEnv, ti.Name)
						}
					}
				}
			}
		}
	}
	// If our basic templates do not parse, it is game over for us
	s.rt.dt.tmplMux.Lock()
	s.tmplMux.Lock()
	root := s.genRoot(s.rt.dt.rootTemplate, s)
	s.rt.dt.tmplMux.Unlock()
	if root != nil {
		s.rootTemplate = root
	}
	s.tmplMux.Unlock()
	// Update renderers on machines
	machines := s.rt.stores("machines")
	if machines != nil && root != nil {
		for _, i := range machines.Items() {
			machine := AsMachine(i)
			if machine.Stage != s.Name {
				continue
			}
			s.renderers = append(s.renderers, s.render(s.rt, machine, s)...)
		}
	}
	s.SetAvailable()
	workflows := s.rt.stores("workflows")
	if workflows != nil {
		for _, i := range workflows.Items() {
			workflow := AsWorkflow(i)
			for _, stageName := range workflow.Stages {
				if stageName != s.Name {
					continue
				}
				func() {
					workflow.rt = s.rt
					defer func() { workflow.rt = nil }()
					workflow.ClearValidation()
					workflow.Validate()
				}()
			}
			break
		}
	}
}

// OnLoad initializes the Stage when loaded by the data store.
func (s *Stage) OnLoad() error {
	defer func() { s.rt = nil }()
	s.Fill()
	return s.BeforeSave()
}

// New returns a new empty Stage with the ForceChange
// and RT fields of the calling Stage as store.KeySaver
// for the data store.
func (s *Stage) New() store.KeySaver {
	res := &Stage{Stage: &models.Stage{}}
	if s.Stage != nil && s.ChangeForced() {
		res.ForceChange()
	}
	res.rt = s.rt
	res.Fill()
	return res
}

// BeforeSave returns an error if the Stage
// is not valid to abort the Save.
func (s *Stage) BeforeSave() error {
	s.Fill()
	s.Validate()
	if !s.Validated {
		return s.MakeError(422, ValidationError, s)
	}
	return nil
}

// BeforeDelete returns an error if the Stage is
// in use by a workflow or machine to abort the
// delete.
func (s *Stage) BeforeDelete() error {
	e := &models.Error{Code: 409, Type: StillInUseError, Model: s.Prefix(), Key: s.Key()}
	machines := s.rt.stores("machines")
	for _, i := range machines.Items() {
		machine := AsMachine(i)
		if machine.Stage != s.Name {
			continue
		}
		e.Errorf("Stage %s in use by Machine %s", s.Name, machine.Name)
	}
	workflows := s.rt.stores("workflows")
	for _, i := range workflows.Items() {
		workflow := AsWorkflow(i)
		for _, stageName := range workflow.Stages {
			if stageName != s.Name {
				continue
			}
			e.Errorf("Stage %s in use by Workflow %s", s.Name, workflow.Name)
		}
	}
	return e.HasError()
}

// AsStage converts the models.Model into a *Stage.
func AsStage(o models.Model) *Stage {
	return o.(*Stage)
}

// AsStages converts the list of models.Model into a list of *Stage.
func AsStages(o []models.Model) []*Stage {
	res := make([]*Stage, len(o))
	for i := range o {
		res[i] = AsStage(o[i])
	}
	return res
}

func (s *Stage) renderInfo() ([]models.TemplateInfo, []string) {
	return s.Templates, s.RequiredParams
}

func (s *Stage) templates() *template.Template {
	return s.rootTemplate
}

func (s *Stage) render(rt *RequestTracker, m *Machine, e models.ErrorAdder) renderers {
	if len(s.RequiredParams) > 0 && m == nil {
		e.Errorf("Machine is nil or does not have params")
		return nil
	}
	r := newRenderData(rt, m, s)
	return r.makeRenderers(e)
}

// AfterSave registers new renderers after successful save.
func (s *Stage) AfterSave() {
	if s.Available && s.renderers != nil {
		s.renderers.register(s.rt)
	}
	s.renderers = nil
}

var stageLockMap = map[string][]string{
	"get":     {"stages", "params"},
	"create":  {"stages", "bootenvs", "machines", "tasks", "templates", "profiles", "workflows", "params"},
	"update":  {"stages", "bootenvs", "machines", "tasks", "templates", "profiles", "workflows", "params"},
	"patch":   {"stages", "bootenvs", "machines", "tasks", "templates", "profiles", "workflows", "params"},
	"delete":  {"stages", "bootenvs", "machines", "tasks", "templates", "profiles", "workflows", "params"},
	"actions": {"stages", "profiles", "params"},
}

// Locks returns a list of prefixes that need to be locked for the specific action.
func (s *Stage) Locks(action string) []string {
	return stageLockMap[action]
}
