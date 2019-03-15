package backend

import (
	"strings"
	"sync"
	"text/template"

	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/store"
)

// Task is a thing that can run on a Machine.
type Task struct {
	*models.Task
	validate
	rootTemplate *template.Template
	tmplMux      sync.Mutex
}

func (t *Task) sanityCheck(rt *RequestTracker, e models.ErrorAdder, seen map[string]int) (prereqs []string, sane bool) {
	prereqs = []string{}
	sane = true
	if idx, ok := seen[t.Name]; ok {
		sane = false
		s := make([]string, len(seen))
		for v, i := range seen {
			s[i] = v
		}
		if idx == 0 {
			e.Errorf("Task %s depends on itself!", t.Name)
		} else {
			e.Errorf("Task %s depends on a task with a circular dependency", t.Name)
		}
		e.Errorf("%v: %v (cycle at %d)", strings.Join(s, ": "), t.Name, idx)
		return
	}
	if len(t.Prerequisites) == 0 {
		return
	}
	seen[t.Name] = len(seen)
	for _, prereq := range t.Prerequisites {
		pq := rt.find("tasks", prereq)
		if pq == nil {
			sane = false
			e.Errorf("Task %s missing prerequisite %s", t.Name, prereq)
			continue
		}
		cpr, cSane := AsTask(pq).sanityCheck(rt, e, seen)
		sane = sane && cSane
		prereqs = append(prereqs, cpr...)
	}
	prereqs = append(prereqs, t.Prerequisites...)
	delete(seen, t.Name)
	return
}

func recalcTaskSanity(rt *RequestTracker) {
	for _, item := range rt.stores("tasks").Items() {
		task := AsTask(item)
		task.sanityCheck(rt, task, map[string]int{})
	}
}

// SaveClean clears validation and returns the object as a KeySaver.
func (t *Task) SaveClean() store.KeySaver {
	mod := *t.Task
	mod.ClearValidation()
	return toBackend(&mod, t.rt)
}

// AsTask converts a models.Model to a *Task.
func AsTask(o models.Model) *Task {
	return o.(*Task)
}

// AsTasks converts a list of models.Model to a list of *Task.
func AsTasks(o []models.Model) []*Task {
	res := make([]*Task, len(o))
	for i := range o {
		res[i] = AsTask(o[i])
	}
	return res
}

// New returns an empty new Task with the forceChange
// and RT fields inherited from the caller.
func (t *Task) New() store.KeySaver {
	res := &Task{Task: &models.Task{}}
	if t.Task != nil && t.ChangeForced() {
		res.ForceChange()
	}
	res.rt = t.rt
	return res
}

// Indexes returns the valid indexes for a Task.
func (t *Task) Indexes() map[string]index.Maker {
	fix := AsTask
	res := index.MakeBaseIndexes(t)
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
			task := fix(t.New())
			task.Name = s
			return task, nil
		})
	return res
}

func (t *Task) genRoot(common *template.Template, e models.ErrorAdder) *template.Template {
	res := models.MergeTemplates(common, t.Templates, e)
	if e.HasError() != nil {
		return nil
	}
	return res
}

// Validate tests the validity of Task.  Including revalidating
// referencing stages.
func (t *Task) Validate() {
	t.Task.Validate()
	t.rt.dt.tmplMux.Lock()
	t.tmplMux.Lock()
	root := t.genRoot(t.rt.dt.rootTemplate, t)
	t.rt.dt.tmplMux.Unlock()
	t.sanityCheck(t.rt, t, map[string]int{})
	t.SetValid()
	if t.Useable() {
		t.rootTemplate = root
		t.SetAvailable()
	}
	t.tmplMux.Unlock()

	stages := t.rt.stores("stages")
	if stages != nil {
		for _, i := range stages.Items() {
			stage := AsStage(i)
			if stage.Tasks == nil || len(stage.Tasks) == 0 {
				continue
			}
			for _, taskName := range stage.Tasks {
				if taskName != t.Name {
					continue
				}
				rt := t.rt
				rt.RunAfter(func() {
					stage.rt = rt
					defer func() { stage.rt = nil }()
					stage.Validate()
				})
				break
			}
		}
	}
	return
}

// BeforeSave makes sure the Task is valid and returns an error if not.
// This is used to abort saving invalid objects.
func (t *Task) BeforeSave() error {
	t.Validate()
	if !t.HasFeature("sane-exit-codes") {
		t.AddFeature("original-exit-codes")
	}
	if !t.Useable() {
		return t.MakeError(422, ValidationError, t)
	}
	return nil
}

func (t *Task) OnLoad() error {
	defer func() { t.rt = nil }()
	t.Fill()
	return t.BeforeSave()
}

func (t *Task) AfterSave() {
	recalcTaskSanity(t.rt)
}

type taskHaver interface {
	models.Model
	HasTask(string) bool
}

// BeforeDelete makes sure that the task is not referenced before deleteing.
func (t *Task) BeforeDelete() error {
	e := &models.Error{Code: 409, Type: StillInUseError, Model: t.Prefix(), Key: t.Key()}
	for _, objPrefix := range []string{"machines", "stages"} {
		for _, j := range t.rt.stores(objPrefix).Items() {
			thing := j.(taskHaver)
			if thing.HasTask(t.Name) {
				e.Errorf("%s:%s still uses %s", thing.Prefix(), thing.Key(), t.Name)
			}
		}
	}
	return e.HasError()
}

func (t *Task) AfterDelete() {
	recalcTaskSanity(t.rt)
}

func (t *Task) renderInfo() ([]models.TemplateInfo, []string) {
	return t.Templates, t.RequiredParams
}

func (t *Task) templates() *template.Template {
	return t.rootTemplate
}

// render builds list of renderers that can be used to render all the templates
// associated with this task.
func (t *Task) render(rt *RequestTracker, m *Machine, e *models.Error) renderers {
	if m == nil {
		e.Errorf("No machine to render against")
		return nil
	}
	r := newRenderData(rt, m, t)
	return r.makeRenderers(e)
}

var taskLockMap = map[string][]string{
	"get":     {"templates", "tasks"},
	"create":  {"stages", "machines", "templates", "tasks", "bootenvs", "workflows", "profiles"},
	"update":  {"stages", "machines", "templates", "tasks", "bootenvs", "workflows", "profiles"},
	"patch":   {"stages", "machines", "templates", "tasks", "bootenvs", "workflows", "profiles"},
	"delete":  {"stages", "tasks", "machines", "workflows", "profiles"},
	"actions": {"tasks", "profiles", "params"},
}

// Locks returns a list of prefixes to lock for a specific action.
func (t *Task) Locks(action string) []string {
	return taskLockMap[action]
}
