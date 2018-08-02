package backend

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/store"
)

// Template represents a template that will be associated with a boot
// environment.
type Template struct {
	*models.Template
	validate
	toUpdate *tmplUpdater
}

// SetReadOnly helper function to set ReadOnly
func (t *Template) SetReadOnly(b bool) {
	t.ReadOnly = b
}

// SaveClean clears the validation fields and returns the
// object as a KeySaver for use in the backing stores.
func (t *Template) SaveClean() store.KeySaver {
	mod := *t.Template
	mod.ClearValidation()
	return toBackend(&mod, t.rt)
}

// Indexes returns a map of valid indexes for Template
func (t *Template) Indexes() map[string]index.Maker {
	fix := AsTemplate
	res := index.MakeBaseIndexes(t)
	res["ID"] = index.Make(
		true,
		"string",
		func(i, j models.Model) bool { return fix(i).ID < fix(j).ID },
		func(ref models.Model) (gte, gt index.Test) {
			refID := fix(ref).ID
			return func(s models.Model) bool {
					return fix(s).ID >= refID
				},
				func(s models.Model) bool {
					return fix(s).ID > refID
				}
		},
		func(s string) (models.Model, error) {
			tmpl := fix(t.New())
			tmpl.ID = s
			return tmpl, nil
		})
	return res
}

// New returns a new empty Template with the ForceChange
// RT fields initialized from the calling object.
func (t *Template) New() store.KeySaver {
	res := &Template{Template: &models.Template{}}
	if t.Template != nil && t.ChangeForced() {
		res.ForceChange()
	}
	res.rt = t.rt
	return res
}

func (t *Template) parse(root *template.Template) error {
	_, err := root.New(t.ID).Parse(t.Contents)
	return err
}

type tmplUpdater struct {
	root                            *template.Template
	tasks                           []*Task
	bootenvs                        []*BootEnv
	stages                          []*Stage
	taskTmpls, envTmpls, stageTmpls []*template.Template
}

func (t *Template) checkSubs(root *template.Template, e models.ErrorAdder) {
	t.toUpdate = &tmplUpdater{root: root, tasks: []*Task{}, bootenvs: []*BootEnv{}}
	if foo := t.rt.stores("tasks"); foo != nil {
		t.toUpdate.tasks = AsTasks(foo.Items())
	}
	if foo := t.rt.stores("bootenvs"); foo != nil {
		t.toUpdate.bootenvs = AsBootEnvs(foo.Items())
	}
	if foo := t.rt.stores("stages"); foo != nil {
		t.toUpdate.stages = AsStages(foo.Items())
	}
	t.toUpdate.taskTmpls = make([]*template.Template, len(t.toUpdate.tasks))
	t.toUpdate.envTmpls = make([]*template.Template, len(t.toUpdate.bootenvs))
	t.toUpdate.stageTmpls = make([]*template.Template, len(t.toUpdate.stages))
	for i, task := range t.toUpdate.tasks {
		t.toUpdate.taskTmpls[i] = task.genRoot(root, e)
	}
	for i, bootenv := range t.toUpdate.bootenvs {
		t.toUpdate.envTmpls[i] = bootenv.genRoot(root, e)
	}
	for i, stage := range t.toUpdate.stages {
		t.toUpdate.stageTmpls[i] = stage.genRoot(root, e)
	}
}

// Validate makes sure that the template is valid.
// It sets the valid and available fields.
func (t *Template) Validate() {
	t.Template.Validate()
	var err error
	t.rt.dt.tmplMux.Lock()
	root := t.rt.dt.rootTemplate
	if root == nil {
		root = template.New("").Funcs(models.DrpSafeFuncMap())
	} else {
		root, err = root.Clone()
	}
	t.rt.dt.tmplMux.Unlock()
	if err != nil {
		t.Errorf("Error cloning shared template namespace: %v", err)
		return
	}
	if err := t.parse(root); err != nil {
		t.Errorf("Parse error for template %s: %v", t.ID, err)
		return
	}
	t.AddError(index.CheckUnique(t, t.rt.stores("templates").Items()))
	if t.HasError() != nil {
		return
	}
	t.checkSubs(root, t)
	t.SetValid()
	t.SetAvailable()
}

// BeforeSave makes sure that the template is valid and returns
// an error otherwise.
func (t *Template) BeforeSave() error {
	t.Validate()
	if !t.Useable() {
		return t.MakeError(422, ValidationError, t)
	}
	return nil
}

// OnLoad initializes the Template when loading from backing store.
func (t *Template) OnLoad() error {
	defer func() { t.rt = nil }()
	t.Fill()
	t.Validated = true
	t.Available = true
	return nil
}

func (t *Template) updateOthers() {
	t.rt.dt.tmplMux.Lock()
	t.rt.dt.rootTemplate = t.toUpdate.root
	t.rt.dt.tmplMux.Unlock()
	for i, task := range t.toUpdate.tasks {
		task.tmplMux.Lock()
		task.rootTemplate = t.toUpdate.taskTmpls[i]
		task.tmplMux.Unlock()
	}
	for i, bootenv := range t.toUpdate.bootenvs {
		bootenv.tmplMux.Lock()
		bootenv.rootTemplate = t.toUpdate.envTmpls[i]
		bootenv.tmplMux.Unlock()
	}
	t.toUpdate = nil
}

// AfterSave updates referencing objects after a save to the
// backing store.
func (t *Template) AfterSave() {
	t.updateOthers()
}

// BeforeDelete returns an error if this template is still
// referenced before a delete is done.  No error implies
// can be deleted.
func (t *Template) BeforeDelete() error {
	e := &models.Error{Code: 409, Type: StillInUseError, Model: t.Prefix(), Key: t.Key()}
	buf := &bytes.Buffer{}
	for _, i := range t.rt.stores("templates").Items() {
		tmpl := AsTemplate(i)
		if tmpl.ID == t.ID {
			continue
		}
		fmt.Fprintf(buf, `{{define "%s"}}%s{{end}}\n`, tmpl.ID, tmpl.Contents)
	}
	root, err := template.New("").Funcs(models.DrpSafeFuncMap()).Parse(buf.String())
	if err != nil {
		e.Errorf("Template %s still required: %v", t.ID, err)
		return e
	}
	t.checkSubs(root, e)
	if e.ContainsError() {
		return e
	}
	t.updateOthers()
	return nil
}

// AsTemplate converts a models.Model into a *Template
func AsTemplate(o models.Model) *Template {
	return o.(*Template)
}

// AsTemplates converts a list of models.Model into a list of *Template
func AsTemplates(o []models.Model) []*Template {
	res := make([]*Template, len(o))
	for i := range o {
		res[i] = AsTemplate(o[i])
	}
	return res
}

var templateLockMap = map[string][]string{
	"get":     {"templates"},
	"create":  {"stages", "templates", "bootenvs", "machines", "tasks"},
	"update":  {"stages", "templates", "bootenvs", "machines", "tasks"},
	"patch":   {"stages", "templates", "bootenvs", "machines", "tasks"},
	"delete":  {"stages", "templates", "bootenvs", "machines", "tasks"},
	"actions": {"templates", "profiles", "params"},
}

// Locks returns the list of objects that need to be locked for the specified action.
func (t *Template) Locks(action string) []string {
	return templateLockMap[action]
}
