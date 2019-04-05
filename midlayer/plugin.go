package midlayer

import (
	"fmt"
	"net"
	"reflect"
	"time"

	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
)

const (
	PLUGIN_CREATED     int = 1
	PLUGIN_STARTED     int = 2
	PLUGIN_CONFIGED    int = 3
	PLUGIN_STOPPED     int = 4
	PLUGIN_REMOVED     int = 5
	PLUGIN_CONFIGURING int = 6
	PLUGIN_SHOULD_STOP int = 7
)

type RunningPlugin struct {
	Plugin   *models.Plugin
	Provider *models.PluginProvider
	Client   *PluginClient
	state    int
}

/*
 * There are 6 backend events the drive plugin operations
 *   plugin.create  - Add plugin to running plugins list as Requested - generate start event
 *   plugin.update  - Difference plugins to see if restart is needed - generate stop/start events
 *   plugin.save    - Difference plugins to see if restart is needed - generate stop/start events
 *   plugin.delete  - Remove plugin from system - Generate stop and remove event
 *
 *   plugin_provider.create  - Plugin Provider created by frontend or startup - generate create and start events
 *   plugin_provider.delete  - Plugin Provider deleted by frontend - generate stop events
 *
 * There are 3 internal events
 *   plugin.start   - Plugin should be started
 *   plugin.stop    - Plugin should be stopped
 *   plugin.remove  - Plugin should be removed
 */

/*
 * This a separate go func for handling starting and stopping plugins.
 *
 * All actions are handled from this thread.
 */
func (pc *PluginController) handleEvent(event *models.Event) {
	switch event.Type {
	case "plugins", "plugin":
		plugin, _ := event.Model()
		switch event.Action {
		// API Actions
		case "create":
			pc.createPlugin(plugin)
		case "save", "update":
			pc.restartPlugin(plugin)
		case "delete":
			pc.deletePlugin(plugin)

		// State Actions
		case "start":
			pc.startPlugin(plugin)
		case "config":
			pc.configPlugin(plugin)
		case "stop":
			pc.stopPlugin(plugin)
		case "remove":
			pc.removePlugin(plugin)
		}
	// These generate events which get handled above.
	case "plugin_providers", "plugin_provider":
		pc.lock.Lock()
		defer pc.lock.Unlock()
		switch event.Action {
		case "create":
			pc.allPlugins(event.Key, "start")
		case "delete":
			pc.allPlugins(event.Key, "stop")
		case "retry":
			pc.Panicf("Should never happen")
		}
	case "contents":
		pc.lock.Lock()
		defer pc.lock.Unlock()
		providers, err := pc.define(pc.Request(), pc.dt.FileRoot)
		if err != nil {
			return
		}
		toStop, toStart := []*models.PluginProvider{}, []*models.PluginProvider{}
		for k, v := range pc.AvailableProviders {
			if _, ok := providers[k]; !ok {
				toStop = append(toStop, v)
			}
		}
		for k, v := range providers {
			if _, ok := pc.AvailableProviders[k]; !ok {
				toStart = append(toStart, v)
			}
		}
		for _, v := range toStop {
			pc.allPlugins(v.Name, "stop")
			delete(pc.AvailableProviders, v.Name)
		}
		for _, v := range toStart {
			pc.AvailableProviders[v.Name] = v
			pc.allPlugins(v.Name, "start")
		}
	}
}

func (pc *PluginController) StartPlugins(dt *backend.DataTracker, providers map[string]*models.PluginProvider) {
	pc.lock.Lock()
	defer pc.lock.Unlock()
	pc.dt = dt

	pc.AvailableProviders = providers

	// Get all the plugins that have this as provider
	ref := &backend.Plugin{}
	rt := pc.Request(ref.Locks("get")...)
	rt.Do(func(d backend.Stores) {
		for k, v := range providers {
			rt.Publish("plugin_providers", "create", k, v)
		}
	})
}

func (pc *PluginController) RestartPlugins() {
	pc.lock.Lock()
	defer pc.lock.Unlock()

	// Get all the plugins that have this as provider
	ref := &backend.Plugin{}
	rt := pc.Request(ref.Locks("get")...)
	rt.Do(func(d backend.Stores) {
		var idx *index.Index
		idx, err := index.All([]index.Filter{index.Native()}...)(&d(ref.Prefix()).Index)
		if err != nil {
			return
		}
		arr := idx.Items()
		for _, res := range arr {
			plugin := res.(*backend.Plugin)
			// If we don't know about this plugin yet, create it on the running list
			if _, ok := pc.runningPlugins[plugin.Name]; !ok {
				rt.PublishEvent(models.EventFor(plugin, "create"))
			} else {
				rt.PublishEvent(models.EventFor(plugin, "stop"))
			}
			rt.PublishEvent(models.EventFor(plugin, "start"))
		}
	})
	return
}

func (pc *PluginController) allPlugins(provider, action string) (err error) {
	// Get all the plugins that have this as provider
	ref := &backend.Plugin{}
	rt := pc.Request(ref.Locks("get")...)
	rt.Do(func(d backend.Stores) {
		var idx *index.Index
		idx, err = index.All([]index.Filter{index.Native()}...)(&d(ref.Prefix()).Index)
		if err != nil {
			return
		}
		arr := idx.Items()
		for _, res := range arr {
			plugin := res.(*backend.Plugin)
			if plugin.Provider == provider {
				// If we don't know about this plugin yet, create it on the running list
				if _, ok := pc.runningPlugins[plugin.Name]; !ok {
					if action == "start" {
						rt.PublishEvent(models.EventFor(plugin, "create"))
					}
				}
				if action == "stop" {
					rt.PublishEvent(models.EventFor(plugin, "stop"))
				}
				// We even start on stop to get the error in place.
				rt.PublishEvent(models.EventFor(plugin, "start"))
			}
		}
	})

	// Stop all those that might have disappeared from the database if content provided
	if action == "stop" {
		for _, rp := range pc.runningPlugins {
			if rp.Provider != nil && rp.Provider.Name == provider && rp.Plugin != nil {
				rt.PublishEvent(models.EventFor(rp.Plugin, "stop"))
			}
		}
	}

	return
}

// Must be called under rt.Do()
func validateParameters(rt *backend.RequestTracker, pp *models.PluginProvider, plugin *models.Plugin) []string {
	errors := []string{}
	for _, parmName := range pp.RequiredParams {
		obj, ok := plugin.Params[parmName]
		if !ok {
			errors = append(errors, fmt.Sprintf("Missing required parameter: %s", parmName))
		} else {
			pobj := rt.Find("params", parmName)
			if pobj != nil {
				rp := pobj.(*backend.Param)
				if pk, pkerr := rt.PrivateKeyFor(plugin); pkerr == nil {
					if ev := rp.ValidateValue(obj, pk); ev != nil {
						errors = append(errors, ev.Error())
					}
				} else {
					errors = append(errors, pkerr.Error())
				}
			}
		}
	}
	for _, parmName := range pp.OptionalParams {
		obj, ok := plugin.Params[parmName]
		if ok {
			pobj := rt.Find("params", parmName)
			if pobj != nil {
				rp := pobj.(*backend.Param)
				if pk, pkerr := rt.PrivateKeyFor(plugin); pkerr == nil {
					if ev := rp.ValidateValue(obj, pk); ev != nil {
						errors = append(errors, ev.Error())
					}
				} else {
					errors = append(errors, pkerr.Error())
				}
			}
		}
	}
	return errors
}

//
// State machine functions
//

/*
 * Regardless of state, make sure we have a running plugin.
 *
 * PLUGIN_CREATED    : send start event
 * PLUGIN_STARTED    : send start event
 * PLUGIN_CONFIGED   : send start event
 * PLUGIN_STOPPED    : send start event
 * PLUGIN_REMOVED    : send start event
 * PLUGIN_CONFIGURING: send start event
 * PLUGIN_SHOULD_STOP: do nothing
 */
func (pc *PluginController) createPlugin(mp models.Model) {
	pc.lock.Lock()
	defer pc.lock.Unlock()

	plugin := mp.(*models.Plugin)

	ref := &backend.Plugin{}
	rt := pc.Request(ref.Locks("get")...)

	if r, ok := pc.runningPlugins[plugin.Name]; ok && r.state == PLUGIN_CREATED {
		pc.Infof("Already created plugin %s. Updating model", plugin.Name)
		r.Plugin = plugin
	} else if ok && r.state == PLUGIN_SHOULD_STOP {
		pc.Infof("Already created plugin %s, but should stop - do nothing", plugin.Name)
	} else if ok {
		pc.Errorf("Plugin %s is already created and in process.  Update model", r.Plugin.Name)
		r.Plugin = plugin
	} else {
		pc.runningPlugins[plugin.Name] = &RunningPlugin{Plugin: plugin, state: PLUGIN_CREATED}
	}
	rt.PublishEvent(models.EventFor(plugin, "start"))
}

/*
 * Start the Plugin
 *
 * not found         : send create event
 * PLUGIN_CREATED    : start binary, state to PLUGIN_STARTED, send config event
 * PLUGIN_STARTED    : send config event
 * PLUGIN_CONFIGED   : do nothing
 * PLUGIN_STOPPED    : start binary, state to PLUGIN_STARTED, send config event
 * PLUGIN_REMOVED    : do nothing
 * PLUGIN_CONFIGURING: do nothing
 * PLUGIN_SHOULD_STOP: do nothing
 *
 * if start has error, go to PLUGIN_STOPPED
 */
func (pc *PluginController) startPlugin(mp models.Model) {
	pc.lock.Lock()
	defer pc.lock.Unlock()

	plugin := mp.(*models.Plugin)

	ref := &backend.Plugin{}
	rt := pc.Request(ref.Locks("get")...)
	rt.Do(func(d backend.Stores) {
		ref2 := rt.Find("plugins", plugin.Name)

		r, ok := pc.runningPlugins[plugin.Name]
		if !ok && ref2 == nil {
			// The plugin is deleted and not present.
			pc.Errorf("Plugin delete before starting. %v\n", plugin)
			return
		} else if !ok && ref2 != nil {
			pc.Infof("Plugin wants to be started, but isn't created, create it: %s\n", plugin.Name)
			rt.PublishEvent(models.EventFor(plugin, "create"))
			return
		} else if r.state == PLUGIN_STARTED {
			pc.Infof("Plugin %s is already started. Try to config it", plugin.Name)
			rt.PublishEvent(models.EventFor(plugin, "config"))
			return
		} else if r.state != PLUGIN_CREATED && r.state != PLUGIN_STOPPED {
			pc.Infof("Plugin %s not in correct state to start, just return", plugin.Name)
			return
		}

		r.Plugin = plugin

		pp, ok := pc.AvailableProviders[plugin.Provider]
		if !ok {
			r.state = PLUGIN_STOPPED
			pc.Errorf("Starting plugin: %s(%s) missing provider\n", plugin.Name, plugin.Provider)
			if plugin.PluginErrors == nil || len(plugin.PluginErrors) == 0 {
				plugin.PluginErrors = []string{fmt.Sprintf("Missing Plugin Provider: %s", plugin.Provider)}
				rt.Update(plugin)
				pc.events <- &models.Event{Action: "retry", Key: plugin.Provider, Type: "plugin_providers"}
			}
			return
		}

		r.Provider = pp

		errors := validateParameters(rt, pp, plugin)
		if len(errors) > 0 {
			r.state = PLUGIN_STOPPED
			if plugin.PluginErrors == nil {
				plugin.PluginErrors = []string{}
			}
			if len(plugin.PluginErrors) != len(errors) {
				plugin.PluginErrors = errors
				rt.Update(plugin)
			}
			return
		}

		claims := backend.NewClaim(plugin.Name, "system", time.Hour*1000000).
			AddRawClaim("*", "*", "*").
			AddSecrets("", "", "")
		token, _ := rt.SealClaims(claims)
		ppath := pc.pluginDir + "/" + pp.Name
		thingee, err := NewPluginClient(
			pc,
			pc.pluginCommDir,
			plugin.Name,
			plugin.Provider,
			pc.Logger.Fork().SetService(plugin.Name).SetPrincipal(plugin.Provider),
			rt.ApiURL(net.ParseIP("0.0.0.0")),
			rt.FileURL(net.ParseIP("0.0.0.0")),
			token,
			ppath)

		if err != nil {
			if len(r.Plugin.PluginErrors) == 0 {
				r.Plugin.PluginErrors = []string{err.Error()}
				rt.Update(r.Plugin)
			}
			r.state = PLUGIN_STOPPED
		} else {
			r.Client = thingee
			r.state = PLUGIN_STARTED

			if len(r.Plugin.PluginErrors) > 0 {
				r.Plugin.PluginErrors = []string{}
				rt.Update(r.Plugin)
			}
			rt.PublishEvent(models.EventFor(r.Plugin, "config"))
		}
	})
}

/*
 * Config the Plugin
 *
 * not found         : assume deleted - do nothing
 * PLUGIN_CREATED    : send start event
 * PLUGIN_STARTED    : mark start PLUGIN_CONFIGURING, unlock, do config, relock, and mark STOPPED or CONFIGED
 * PLUGIN_CONFIGED   : do nothing
 * PLUGIN_STOPPED    : Force a failure to STOPPED
 * PLUGIN_REMOVED    : Force a failure to STOPPED
 * PLUGIN_CONFIGURING: do nothing
 * PLUGIN_SHOULD_STOP: Force a failure to STOPPED.
 *
 * if start has error, go to PLUGIN_STOPPED
 */
func (pc *PluginController) configPlugin(mp models.Model) {
	pc.lock.Lock()
	defer pc.lock.Unlock()

	ref := &backend.Plugin{}
	rt := pc.Request(ref.Locks("get")...)

	plugin := mp.(*models.Plugin)

	r, ok := pc.runningPlugins[plugin.Name]
	if !ok {
		// The plugin is deleted and not present.
		pc.Errorf("Plugin delete before config. %v\n", plugin.Name)
		return
	} else if r.state == PLUGIN_CONFIGED {
		pc.Infof("Plugin %s is already configed. Done!", plugin.Name)
		return
	} else if r.state != PLUGIN_STARTED {
		pc.Infof("Plugin %s isn't started. do nothing ", plugin.Name)
		return
	} else if r.state == PLUGIN_CONFIGURING {
		pc.Infof("Plugin %s is in the config process", plugin.Name)
		return
	}

	r.state = PLUGIN_CONFIGURING

	for obj, props := range r.Provider.StoreObjects {
		// Turn the fields into a json object schema
		schema := map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"Id": map[string]interface{}{
					"type":       "string",
					"isrequired": true,
				},
				"Type": map[string]interface{}{
					"type":       "string",
					"isrequired": true,
				},
			},
		}
		m := schema["properties"].(map[string]interface{})
		for field, s := range props.(map[string]interface{}) {
			m[field] = s
		}
		required := []string{}
		for field, s := range m {
			data := s.(map[string]interface{})
			if rb, ok := data["isrequired"]; ok {
				if b, ok := rb.(bool); ok && b {
					required = append(required, field)
				}
			}
		}
		schema["required"] = required

		// Register with the backend - DO NOT RUN Under RT Lock
		if err := pc.dt.AddStoreType(obj, schema); err != nil {
			r.Client.Errorf("failed to register object type: %s: %v\n", obj, err)
		}
		// Register with the frontend
		pc.AddStorageType(obj)
	}

	pc.lock.Unlock()

	params := map[string]interface{}{}
	// Plugins should take advantage of defaults
	for k, v := range plugin.Params {
		params[k] = v
	}
	rt.Do(func(d backend.Stores) {
		for _, name := range r.Provider.RequiredParams {
			if _, ok := params[name]; ok {
				continue
			}
			if v, ok := rt.GetParam(plugin, name, true, true); ok {
				params[name] = v
			}
		}
		for _, name := range r.Provider.OptionalParams {
			if _, ok := params[name]; ok {
				continue
			}
			if v, ok := rt.GetParam(plugin, name, true, true); ok {
				params[name] = v
			}
		}
	})

	// Configure the plugin
	pc.Debugf("Config Plugin: %s\n", plugin)
	terr := r.Client.Config(params)

	pc.lock.Lock()

	if terr != nil || r.state != PLUGIN_CONFIGURING {
		r.Client.Infof("Stop Plugin: %s Error: %v\n", plugin, terr)
		r.Client.Stop()
		r.Client = nil
		r.state = PLUGIN_STOPPED
		rt.Do(func(d backend.Stores) {
			ref2 := rt.Find("plugins", plugin.Name)
			if ref2 == nil {
				return
			}
			r.Plugin = plugin

			if len(r.Plugin.PluginErrors) == 0 {
				r.Plugin.PluginErrors = []string{terr.Error()}
				rt.Update(r.Plugin)
			}
		})

		// If we got permission denied, we need to remove the plugin provider.
		if berr, ok := terr.(*models.Error); ok && berr.Code == 403 {
			pc.removePluginProvider(rt, r.Plugin.Provider)
		}
		return
	}

	r.state = PLUGIN_CONFIGED
	if r.Provider.HasPublish {
		pc.publishers.Add(r.Client)
	}
	for i := range r.Provider.AvailableActions {
		r.Provider.AvailableActions[i].Fill()
		r.Provider.AvailableActions[i].Provider = r.Provider.Name
		pc.Actions.Add(r.Provider.AvailableActions[i], r)
	}
	rt.Publish("plugins", "configed", plugin.Name, plugin)
}

/*
 * Stop the Plugin
 *
 * not found         : assume deleted - do nothing
 * PLUGIN_CREATED    : mark plugin PLUGIN_STOPPED
 * PLUGIN_STARTED    : Remove touch points, drain callers, stop plugin, makr stopped.
 * PLUGIN_CONFIGED   : Remove touch points, drain callers, stop plugin, makr stopped.
 * PLUGIN_STOPPED    : do nothing
 * PLUGIN_REMOVED    : do nothing
 * PLUGIN_CONFIGURING: Mark state PLUGIN_SHOULD_STOP
 * PLUGIN_SHOULD_STOP: do nothing
 *
 * if start has error, go to PLUGIN_STOPPED
 */
func (pc *PluginController) stopPlugin(mp models.Model) {
	plugin := mp.(*models.Plugin)

	pc.lock.Lock()
	defer pc.lock.Unlock()

	ref := &backend.Plugin{}
	rt := pc.Request(ref.Locks("get")...)

	rp, ok := pc.runningPlugins[plugin.Name]
	if !ok || rp.state == PLUGIN_REMOVED || rp.state == PLUGIN_STOPPED {
		// If we've missing, been removed, or stopped, then done
		return
	}

	if rp.state == PLUGIN_SHOULD_STOP {
		return
	}

	if rp.state == PLUGIN_CONFIGURING {
		rp.state = PLUGIN_SHOULD_STOP
		return
	}

	if rp.state == PLUGIN_STARTED || rp.state == PLUGIN_CONFIGED {
		plugin := rp.Plugin
		rt.Infof("Stopping plugin: %s(%s)\n", plugin.Name, plugin.Provider)

		if rp.Provider.HasPublish {
			rt.Debugf("Remove publisher: %s(%s)\n", plugin.Name, plugin.Provider)
			pc.publishers.Remove(rp.Client)
		}
		for _, aa := range rp.Provider.AvailableActions {
			rt.Debugf("Remove actions: %s(%s,%s)\n", plugin.Name, plugin.Provider, aa.Command)
			pc.Actions.Remove(aa, rp)
		}
		rp.state = PLUGIN_STOPPED

		rt.Debugf("Drain executable: %s(%s)\n", plugin.Name, plugin.Provider)
		rp.Client.Unload()
		rt.Debugf("Stop executable: %s(%s)\n", plugin.Name, plugin.Provider)
		rp.Client.Stop()
		rt.Infof("Stopping plugin: %s(%s) complete\n", plugin.Name, plugin.Provider)
		rt.Publish("plugins", "stopped", plugin.Name, plugin)
	} else {
		pc.Infof("Plugin should be started before stopping!! %v\n", rp.Plugin)
		rp.state = PLUGIN_STOPPED
	}
}

func (pc *PluginController) removePlugin(mp models.Model) {
	plugin := mp.(*models.Plugin)

	pc.lock.Lock()
	defer pc.lock.Unlock()

	rp, ok := pc.runningPlugins[plugin.Name]
	if !ok {
		// If Already gone.
		return
	}
	if rp.state != PLUGIN_STOPPED {
		pc.Errorf("Plugin should be stopped before removing!! %v\n", rp.Plugin)
	}
	rp.state = PLUGIN_REMOVED
	delete(pc.runningPlugins, plugin.Name)
}

/*
 * We've received an update/save to the plugin.  Figure out if
 * we need to stop and start the plugin because of changes.
 */
func (pc *PluginController) restartPlugin(mp models.Model) {
	pc.lock.Lock()
	defer pc.lock.Unlock()

	plugin := mp.(*models.Plugin)

	ref := &backend.Plugin{}
	rt := pc.Request(ref.Locks("get")...)
	rt.Do(func(d backend.Stores) {
		ref2 := rt.Find(ref.Prefix(), plugin.Name)
		// May be deleted before we get here. An event will be around to remove it
		if ref2 != nil {
			p := ref2.(*backend.Plugin)

			if rp, ok := pc.runningPlugins[plugin.Name]; !ok {
				// We did fine our plugin in the list.  Send a create event (which will send a start event)
				// Just in case, we have a race on startup and somebody making changes.  Speed the process along.
				rt.PublishEvent(models.EventFor(p, "create"))
			} else {
				oldP := rp.Plugin
				doit := false
				if p.Description != oldP.Description {
					doit = true
				}
				if p.Provider != oldP.Provider {
					doit = true
				}
				if !reflect.DeepEqual(p.Params, oldP.Params) {
					doit = true
				}
				if doit {
					rt.PublishEvent(models.EventFor(p, "stop"))
					rt.PublishEvent(models.EventFor(p, "start"))
				}
			}
		}
	})
}

/*
 * We've received a delete to the plugin.
 */
func (pc *PluginController) deletePlugin(mp models.Model) {
	plugin := mp.(*models.Plugin)

	ref := &backend.Plugin{}
	rt := pc.Request(ref.Locks("get")...)
	rt.Do(func(d backend.Stores) {
		rt.PublishEvent(models.EventFor(plugin, "stop"))
		rt.PublishEvent(models.EventFor(plugin, "remove"))
	})
}
