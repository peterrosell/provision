package backend

import (
	"testing"

	"github.com/digitalrebar/provision/models"
)

func TestParamsCrud(t *testing.T) {
	dt := mkDT()
	rt := dt.Request(dt.Logger, "profiles", "params")
	tests := []crudTest{
		{"Create empty profile", rt.Create, &models.Param{}, false},
		{"Create new profile with name", rt.Create, &models.Param{Name: "Test Param 0"}, true},
		{"Create new profile with name and schema", rt.Create, &models.Param{
			Name:   "Test Param",
			Schema: map[string]interface{}{},
		}, true},
		{"Create new profile with name and schema", rt.Create, &models.Param{
			Name: "Test Param 2",
			Schema: map[string]interface{}{
				"type": "boolean",
			},
		}, true},
		{"Create Duplicate Param", rt.Create, &models.Param{Name: "Test Param"}, false},
		{"Delete Param", rt.Remove, &models.Param{Name: "Test Param"}, true},
		{"Delete Nonexistent Param", rt.Remove, &models.Param{Name: "Test Param"}, false},
	}
	for _, test := range tests {
		test.Test(t, rt)
	}
	// List test.
	rt.Do(func(d Stores) {
		bes := d("profiles").Items()
		if bes != nil {
			if len(bes) != 1 {
				t.Errorf("List function should have returned: 1, but got %d\n", len(bes))
			}
		} else {
			t.Errorf("List function returned nil!!")
		}
	})
}
