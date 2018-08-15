package backend

import (
	"testing"

	"github.com/digitalrebar/provision/models"
)

func TestTemplateCrud(t *testing.T) {
	dt := mkDT()
	rt := dt.Request(dt.Logger, "stages", "templates", "bootenvs", "tasks", "machines")
	crudTest{"Create Template with No ID", rt.Create, &models.Template{}, false}.Test(t, rt)
	crudTest{"Create Template with Bad / ID", rt.Create, &models.Template{ID: "test/greg"}, false}.Test(t, rt)
	crudTest{"Create Template with Bad \\ ID", rt.Create, &models.Template{ID: "test\\greg"}, false}.Test(t, rt)
	crudTest{"Create Valid Empty Template", rt.Create, &models.Template{ID: "test1"}, true}.Test(t, rt)
	crudTest{"Create Valid Nonempty Template", rt.Create, &models.Template{ID: "test2", Contents: "{{ .Foo }}"}, true}.Test(t, rt)
	crudTest{"Create Duplicate Template", rt.Create, &models.Template{ID: "test1"}, false}.Test(t, rt)
	crudTest{"Create Invalid Template", rt.Create, &models.Template{ID: "test4", Contents: "{{ .Bar }"}, false}.Test(t, rt)
	crudTest{"Create Template that refers to another template", rt.Create, &models.Template{ID: "test3", Contents: `{{template "test2"}}`}, true}.Test(t, rt)
	crudTest{"Update Valid Contents", rt.Update, &models.Template{ID: "test1", Contents: "{{ .Bar }}"}, true}.Test(t, rt)
	crudTest{"Update Invalid Contents", rt.Update, &models.Template{ID: "test1", Contents: "{{}"}, false}.Test(t, rt)
	crudTest{"Update ID", rt.Update, &models.Template{ID: "test5"}, false}.Test(t, rt)
	crudTest{"Update with blank ID", rt.Update, &models.Template{}, false}.Test(t, rt)
	b := &models.BootEnv{Name: "scratch"}
	b.Templates = []models.TemplateInfo{{Name: "ipxe", Path: "default.ipxe", ID: "test1"}}
	var saved bool
	var err error
	rt.Do(func(d Stores) {
		saved, err = rt.Create(b)
	})
	if !saved {
		t.Errorf("Error saving scratch bootenv: %v", err)
	} else {
		t.Logf("Created scratch bootenv")
	}
	crudTest{"Remove Unused Template", rt.Remove, &models.Template{ID: "test2"}, true}.Test(t, rt)
	crudTest{"Remove Used Template", rt.Remove, &models.Template{ID: "test1"}, false}.Test(t, rt)
	rt.Do(func(d Stores) {
		// List test.
		bes := d("templates").Items()
		if bes != nil {
			if len(bes) != 2 {
				t.Errorf("List function should have returned: 2, but got %d\n", len(bes))
			}
		} else {
			t.Errorf("List function returned nil!!")
		}
	})
}
