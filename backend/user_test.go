package backend

import (
	"testing"

	"github.com/digitalrebar/provision/models"
)

func TestUserCrud(t *testing.T) {
	dt := mkDT()
	rt := dt.Request(dt.Logger, "users:rw", "tenants")
	tests := []crudTest{
		{"Create empty user", rt.Create, &models.User{}, false},
		{"Create with bad user /", rt.Create, &models.User{Name: "greg/asdg"}, false},
		{"Create with bad user \\", rt.Create, &models.User{Name: "greg\\agsd"}, false},
		{"Create new user with name", rt.Create, &models.User{Name: "Test User"}, true},
		{"Create Duplicate User", rt.Create, &models.User{Name: "Test User"}, false},
		{"Delete User", rt.Remove, &models.User{Name: "Test User"}, true},
		{"Delete Nonexistent User", rt.Remove, &models.User{Name: "Test User"}, false},
	}
	for _, test := range tests {
		test.Test(t, rt)
	}
	// List test.
	rt.Do(func(d Stores) {
		bes := d("users").Items()
		if bes != nil {
			if len(bes) != 1 {
				t.Errorf("List function should have returned: 1, but got %d\n", len(bes))
			}
		} else {
			t.Errorf("List function returned nil!!")
		}
	})
}

func TestUserPassword(t *testing.T) {
	dt := mkDT()
	rt := dt.Request(dt.Logger, "users:rw", "tenants")
	u := &User{}
	Fill(u)
	u.Name = "test user"
	var saved bool
	var err error
	rt.Do(func(d Stores) {
		saved, err = rt.Create(u)
		if !saved {
			t.Errorf("Unable to create test user: %v", err)
		} else {
			t.Logf("Created test user")
		}
		// should fail because we have no password
		if u.CheckPassword("password") {
			t.Errorf("Checking password should have failed!")
		} else {
			t.Logf("Checking password failed, as expected.")
		}
		// store original secret and change password
		curSecret := u.Secret
		if err := u.ChangePassword(rt, "password"); err != nil {
			t.Errorf("Changing password failed: %v", err)
		} else {
			t.Logf("Changing password passed.")
		}
		// store new secret and check secret was regenerated
		newSecret := u.Secret
		if curSecret == newSecret {
			t.Errorf("Changing password did not regenerate Secret!")
		} else {
			t.Logf("Changing password regenerated Secret")
		}
		// reload the user, then check the password again.
		buf := rt.find("users", "test user")
		if buf == nil {
			t.Errorf("Unable to fetch user from datatracker")
		} else {
			t.Logf("Fetched new user from datatracker cache")
		}
		newU := AsUser(buf)
		if !newU.CheckPassword("password") {
			t.Errorf("Checking password should have succeeded.")
		} else {
			t.Logf("Checking password passed, as expected.")
		}
		// check secret was changed and persisted by ChangePassword above
		if newU.Secret != newSecret {
			t.Errorf("Changing password did not persist new Secret")
		} else {
			t.Logf("Changing password persisted new Secret")
		}
		// Make sure sanitizing the user works as expected
		sanitizedU := newU.Sanitize().(*models.User)
		if len(sanitizedU.PasswordHash) != 0 {
			t.Errorf("Sanitize did not strip out the password hash")
		} else {
			t.Logf("Sanitize stripped out the password hash")
		}
	})
}
