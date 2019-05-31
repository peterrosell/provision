package backend

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/digitalrebar/provision/models"
)

type availableAction struct {
	models.AvailableAction

	plugin *RunningPlugin
	ma     *actions

	lock      sync.Mutex
	inflight  int
	unloading bool
}

/*
 * Actions are maintained in lists in a map of maps.
 * Each action command could be satified by multiple plugins.
 * so each action is stored in a list (one per plugin)
 * The list is stored by command name in a map.
 * The command map is stored by object type.
 *
 * Like this:
 * ObjectType -> Command Name -> list of actions
 */

type AvailableActions []*availableAction
type objectCommands map[string]AvailableActions
type objectsCommands map[string]objectCommands

type actions struct {
	actions objectsCommands
	lock    sync.Mutex
}

func newActions() *actions {
	return &actions{actions: make(objectsCommands, 0)}
}

func (ma *actions) add(model_aa models.AvailableAction, plugin *RunningPlugin) error {
	aa := &availableAction{}
	aa.AvailableAction = model_aa
	aa.plugin = plugin
	aa.ma = ma

	ma.lock.Lock()
	defer ma.lock.Unlock()

	cmdSet := "system"
	if aa.Model != "" {
		cmdSet = aa.Model
	}
	cmd := aa.Command
	pn := aa.plugin.Plugin.Name

	var oc objectCommands
	if toc, ok := ma.actions[cmdSet]; !ok {
		oc = make(objectCommands, 0)
		ma.actions[cmdSet] = oc
	} else {
		oc = toc
	}

	var list AvailableActions
	if tlist, ok := oc[cmd]; !ok {
		list = make(AvailableActions, 0, 0)
		oc[cmd] = list
	} else {
		list = tlist
	}

	for _, laa := range list {
		if laa.plugin.Plugin.Name == pn {
			return fmt.Errorf("Duplicate Action (%s,%s): already present\n", pn, cmd)
		}
	}

	oc[cmd] = append(list, aa)
	return nil
}

func (ma *actions) remove(aa models.AvailableAction, plugin *RunningPlugin) error {
	var err error
	var the_aa *availableAction
	ma.lock.Lock()

	cmdSet := "system"
	if aa.Model != "" {
		cmdSet = aa.Model
	}
	cmd := aa.Command
	pn := plugin.Plugin.Name

	if oc, ok := ma.actions[cmdSet]; !ok {
		err = fmt.Errorf("Missing Action %s: already removed\n", aa.Command)
	} else if list, ok := oc[cmd]; !ok {
		err = fmt.Errorf("Missing Action %s: already removed\n", aa.Command)
	} else {
		newlist := make(AvailableActions, 0, 0)
		for _, laa := range list {
			if pn == laa.plugin.Plugin.Name {
				the_aa = laa
			} else {
				newlist = append(newlist, laa)
			}
		}

		if the_aa == nil {
			err = fmt.Errorf("Missing Action %s: already removed\n", aa.Command)
		} else if len(newlist) > 0 {
			oc[cmd] = newlist
		} else {
			delete(oc, cmd)
			if len(oc) == 0 {
				delete(ma.actions, cmdSet)
			}
		}
	}
	ma.lock.Unlock()

	if the_aa != nil {
		the_aa.unload()
	}

	return err
}

func (ma *actions) list(cmdSet string) []AvailableActions {
	ma.lock.Lock()
	defer ma.lock.Unlock()

	answer := []AvailableActions{}
	if oc, ok := ma.actions[cmdSet]; ok {
		// get the list of keys and sort them
		keys := []string{}
		for key := range oc {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		for _, key := range keys {
			answer = append(answer, oc[key])
		}
	}
	return answer

}

func (ma *actions) get(cmdSet, cmd string) (AvailableActions, bool) {
	ma.lock.Lock()
	defer ma.lock.Unlock()

	if oc, ok := ma.actions[cmdSet]; !ok {
		return nil, false
	} else if tl, ok := oc[cmd]; ok {
		return tl, true
	}
	return nil, false
}

func (ma *actions) getSpecific(cmdSet, cmd, plugin string) (*availableAction, bool) {
	ma.lock.Lock()
	defer ma.lock.Unlock()

	if oc, ok := ma.actions[cmdSet]; !ok {
		return nil, false
	} else if tl, ok := oc[cmd]; ok {
		for _, laa := range tl {
			if laa.plugin.Plugin.Name == plugin {
				return laa, true
			}
		}
	}
	return nil, false
}

func (ma *actions) run(rt *RequestTracker, maa *models.Action) (interface{}, error) {
	var aa *availableAction
	var ok bool
	if maa.Plugin == "" {
		var aas AvailableActions
		aas, ok = ma.get(maa.CommandSet, maa.Command)
		if ok {
			aa = aas[0]
		}
	} else {
		aa, ok = ma.getSpecific(maa.CommandSet, maa.Command, maa.Plugin)
	}
	if !ok {
		return nil, fmt.Errorf("Action no longer available: %s", maa.Command)
	}

	if err := aa.reserve(); err != nil {
		return nil, err
	}
	defer aa.release()

	rt.Debugf("Starting action: %s on %v\n", maa.Command, maa.Model)
	v, e := aa.plugin.Client.Action(rt, maa)
	rt.Debugf("Finished action: %s on %v: %v, %v\n", maa.Command, maa.Model, v, e)
	return v, e
}

func (aa *availableAction) reserve() error {
	aa.lock.Lock()
	defer aa.lock.Unlock()

	if aa.unloading {
		return fmt.Errorf("Action not available %s: unloading", aa.Command)
	}
	aa.inflight += 1
	return nil
}

func (aa *availableAction) release() {
	aa.lock.Lock()
	defer aa.lock.Unlock()

	aa.inflight -= 1
}

func (aa *availableAction) unload() {
	aa.lock.Lock()
	aa.unloading = true
	for aa.inflight != 0 {
		aa.lock.Unlock()
		time.Sleep(time.Millisecond * 15)
		aa.lock.Lock()
	}
	aa.lock.Unlock()
	return
}
