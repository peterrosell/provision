package backend

import (
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/provision/store"
)

// Pref tracks a global DigitalRebar Provision preference -- things like the
// bootenv to use for unknown systems trying to PXE boot to us, the
// default bootenv for known systems, etc.
//
type Pref struct {
	*models.Pref
	validate
}

func (p *Pref) New() store.KeySaver {
	res := &Pref{Pref: &models.Pref{}}
	res.rt = p.rt
	return res
}

func AsPref(v models.Model) *Pref {
	return v.(*Pref)
}

var prefLockMap = map[string][]string{
	"get":     {"preferences"},
	"create":  {"preferences:rw", "bootenvs", "stages", "workflows", "profiles", "params"},
	"update":  {"preferences:rw", "bootenvs", "stages", "workflows", "profiles", "params"},
	"patch":   {"preferences:rw", "bootenvs", "stages", "workflows", "profiles", "params"},
	"delete":  {"preferences:rw", "bootenvs", "stages", "workflows", "profiles", "params"},
	"actions": {"preferences", "profiles", "params", "bootenvs", "stages", "workflows"},
}

func (p *Pref) Locks(action string) []string {
	return prefLockMap[action]
}
