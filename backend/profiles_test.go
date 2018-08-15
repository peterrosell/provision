package backend

import (
	"testing"

	"github.com/digitalrebar/provision/models"
)

func TestProfilesCrud(t *testing.T) {
	dt := mkDT()
	rt := dt.Request(dt.Logger, "stages", "profiles", "params", "machines")
	tests := []crudTest{
		{"Create empty profile", rt.Create, &models.Profile{}, false},
		{"Create new profile with name", rt.Create, &models.Profile{Name: "Test Profile"}, true},
		{"Create Duplicate Profile", rt.Create, &models.Profile{Name: "Test Profile"}, false},
		{"Delete Profile", rt.Remove, &models.Profile{Name: "Test Profile"}, true},
		{"Delete Nonexistent Profile", rt.Remove, &models.Profile{Name: "Test Profile"}, false},
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

func TestProfilesValidation(t *testing.T) {
	dt := mkDT()
	rt := dt.Request(dt.Logger, "profiles", "params")
	tests := []crudTest{
		{
			"Create new Parameter",
			rt.Create,
			&models.Param{
				Name: "Bool",
				Schema: map[string]interface{}{
					"type": "boolean",
				},
			},
			true,
		},
		{
			"Create Passing Profile",
			rt.Create,
			&models.Profile{
				Name: "Bool Profile Pass",
				Params: map[string]interface{}{
					"Bool": true,
				},
			},
			true,
		},
		{
			"Create Failing Profile",
			rt.Create,
			&models.Profile{
				Name: "Bool Profile Fail",
				Params: map[string]interface{}{
					"Bool": "true",
				},
			},
			false,
		},
	}
	for _, test := range tests {
		test.Test(t, rt)
	}
}
