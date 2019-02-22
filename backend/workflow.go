package backend

import (
	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/store"
)

// Workflow is a the backend model wrapper for Workflow.
// This struct also includes validation helpers.
type Workflow struct {
	*models.Workflow
	validate
}

// SetReadOnly is a helper function to set the ReadOnly flag.
func (w *Workflow) SetReadOnly(b bool) {
	w.ReadOnly = b
}

// SaveClean is a helper function to run the model version's
// ClearValidation function before converting back to
// an object that can be stored in the backend.
func (w *Workflow) SaveClean() store.KeySaver {
	mod := *w.Workflow
	mod.ClearValidation()
	return toBackend(&mod, w.rt)
}

// AsWorkflow cast a models.Model interface to
// *Workflow (helper function)
func AsWorkflow(o models.Model) *Workflow {
	return o.(*Workflow)
}

// AsWorkflows converts a list of models.Model to
// a list of *Worfklow (helper function)
func AsWorkflows(o []models.Model) []*Workflow {
	res := make([]*Workflow, len(o))
	for i := range o {
		res[i] = AsWorkflow(o[i])
	}
	return res
}

// New creates a new empty instance of Workflow.
// The ForceChanged and RT fields are propogated.
func (w *Workflow) New() store.KeySaver {
	res := &Workflow{Workflow: &models.Workflow{}}
	if w.Workflow != nil && w.ChangeForced() {
		res.ForceChange()
	}
	res.rt = w.rt
	res.Fill()
	return res
}

// Indexes returns a map of the indexes allowed for
// Workflow objects.
func (w *Workflow) Indexes() map[string]index.Maker {
	fix := AsWorkflow
	res := index.MakeBaseIndexes(w)
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
			res := fix(w.New())
			res.Name = ss
			return res, nil
		})
	return res
}

// Validate sets the valid and available flags
// for the Workflow.  This assumes that locks are
// held as appropriate, if needed.
func (w *Workflow) Validate() {
	w.Workflow.Validate()
	w.AddError(index.CheckUnique(w, w.rt.stores("workflows").Items()))
	if !w.SetValid() {
		return
	}
	for _, stageName := range w.Stages {
		if stage := w.rt.find("stages", stageName); stage == nil {
			w.Errorf("Stage %s does not exist", stageName)
		} else if !stage.(*Stage).Available {
			w.Errorf("Stage %s is not available", stageName)
		}
	}
	w.SetAvailable()
}

// BeforeSave validates the state of the Workflow.
// This is used generally before saving but also
// when an object needs to initialized and
// validated.
func (w *Workflow) BeforeSave() error {
	w.Fill()
	w.Validate()
	if !w.Validated {
		return w.MakeError(422, ValidationError, w)
	}
	return nil
}

// OnLoad initializes the Workflow when loaded from the data store.
func (w *Workflow) OnLoad() error {
	defer func() { w.rt = nil }()
	w.Fill()
	return w.BeforeSave()
}

var workflowLockMap = map[string][]string{
	"get":     {"workflows"},
	"create":  {"stages", "bootenvs", "machines", "tasks", "templates", "profiles", "workflows"},
	"update":  {"stages", "bootenvs", "machines", "tasks", "templates", "profiles", "workflows"},
	"patch":   {"stages", "bootenvs", "machines", "tasks", "templates", "profiles", "workflows"},
	"delete":  {"stages", "bootenvs", "machines", "tasks", "templates", "profiles", "workflows"},
	"actions": {"workflows", "stages", "profiles", "params"},
}

// Locks returns the object lock list for a given action for the Workflow object
func (w *Workflow) Locks(action string) []string {
	return workflowLockMap[action]
}
