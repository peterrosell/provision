package midlayer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/digitalrebar/logger"
	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/store"
	"github.com/gin-gonic/gin"
)

type PluginController struct {
	logger.Logger
	lock               sync.Mutex
	AvailableProviders map[string]*models.PluginProvider
	runningPlugins     map[string]*RunningPlugin
	dt                 *backend.DataTracker
	pluginDir          string
	pluginCommDir      string
	done               chan bool
	finished           chan bool
	events             chan *models.Event
	publishers         *backend.Publishers
	Actions            *Actions
}

func (pc *PluginController) Request(locks ...string) *backend.RequestTracker {
	return pc.dt.Request(pc.Logger, locks...)
}

/*
 * Create contoller and start an event listener.
 */
func InitPluginController(pluginDir, pluginCommDir string, dt *backend.DataTracker, pubs *backend.Publishers) (pc *PluginController, err error) {
	dt.Logger.Debugf("Starting Plugin Controller\n")
	pc = &PluginController{
		Logger:             dt.Logger.Switch("plugin"),
		pluginDir:          pluginDir,
		pluginCommDir:      pluginCommDir,
		dt:                 dt,
		publishers:         pubs,
		AvailableProviders: make(map[string]*models.PluginProvider, 0),
		runningPlugins:     make(map[string]*RunningPlugin, 0)}

	pc.Actions = NewActions()
	pubs.Add(pc)

	pc.done = make(chan bool)
	pc.finished = make(chan bool)
	pc.events = make(chan *models.Event, 1000)

	go func() {
		done := false
		for !done {
			select {
			case event := <-pc.events:
				pc.handleEvent(event)
			case <-pc.done:
				done = true
			}
		}
		pc.finished <- true
	}()
	dt.Logger.Debugf("Returning Plugin Controller: %v\n", err)
	return
}

func ReverseProxy(pc *PluginController) gin.HandlerFunc {
	return func(c *gin.Context) {
		plugin := c.Param(`plugin`)
		socketPath := fmt.Sprintf("%s/%s.toPlugin.%d", pc.pluginCommDir, plugin, pc.getSocketId(plugin))

		url, _ := url.Parse(fmt.Sprintf("http://unix/%s", socketPath))
		proxy := httputil.NewSingleHostReverseProxy(url)
		proxy.Transport = &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		}

		proxy.ServeHTTP(c.Writer, c.Request)
	}
}

func (pc *PluginController) StartRouter(apiGroup *gin.RouterGroup) {
	apiGroup.Any("/plugin-apis/:plugin/*path", ReverseProxy(pc))
}

func (pc *PluginController) StartController() error {
	pc.Debugf("Starting Start Plugin Controller:\n")

	rt := pc.Request()

	pc.StartPlugins()

	pc.lock.Lock()
	defer pc.lock.Unlock()
	// Walk plugin dir contents with lock
	files, err := ioutil.ReadDir(pc.pluginDir)
	if err != nil {
		pc.Tracef("walkPlugDir: finished ReadDir error: %v\n", err)
		return err
	}
	for _, f := range files {
		pc.Debugf("Walk plugin importing: %s\n", f.Name())
		err = pc.importPluginProvider(rt, f.Name())
		if err != nil {
			pc.Tracef("walkPlugDir: importing %s error: %v\n", f.Name(), err)
		}
	}
	pc.Debugf("Finishing Start Plugin Controller: %v\n", err)
	return err
}

func (pc *PluginController) Shutdown(ctx context.Context) error {
	pc.Debugf("Stopping plugin controller\n")
	for _, rp := range pc.runningPlugins {
		pc.Debugf("Stopping plugin: %s\n", rp.Plugin.Name)
		pc.stopPlugin(rp.Plugin)
	}
	pc.Debugf("Stopping plugin gofuncs\n")
	pc.done <- true
	pc.Debugf("Waiting for gofuncs to finish\n")
	<-pc.finished
	pc.Debugf("All stopped\n")
	return nil
}

func (pc *PluginController) Publish(e *models.Event) error {
	switch e.Type {
	case "plugins", "plugin", "plugin_provider", "plugin_providers":
		pc.NoPublish().Tracef("PluginController Publish Event stared: %v\n", e)
		pc.events <- e
		pc.NoPublish().Tracef("PluginController Publish Event finished: %v\n", e)
	}
	return nil
}

// This never gets unloaded.
func (pc *PluginController) Reserve() error {
	return nil
}
func (pc *PluginController) Release() {}
func (pc *PluginController) Unload()  {}

func (pc *PluginController) GetPluginProvider(name string) *models.PluginProvider {
	pc.Tracef("Starting GetPluginProvider\n")
	pc.lock.Lock()
	defer pc.lock.Unlock()

	pc.Debugf("Getting plugin provider for %s\n", name)
	if pp, ok := pc.AvailableProviders[name]; !ok {
		pc.Tracef("Returning GetPluginProvider: null\n")
		return nil
	} else {
		pc.Tracef("Returning GetPluginProvider: <one>\n")
		return pp
	}
}

func (pc *PluginController) GetPluginProviders() []*models.PluginProvider {
	pc.Tracef("Starting GetPluginProviders\n")
	pc.lock.Lock()
	defer pc.lock.Unlock()

	pc.Debugf("Getting all plugin providers\n")
	// get the list of keys and sort them
	keys := []string{}
	for key := range pc.AvailableProviders {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	answer := []*models.PluginProvider{}
	for _, key := range keys {
		answer = append(answer, pc.AvailableProviders[key])
	}
	pc.Tracef("Returning GetPluginProviders: %d\n", len(answer))
	return answer
}

func (pc *PluginController) buildNewStore(content *models.Content) (newStore store.Store, err error) {
	filename := fmt.Sprintf("memory:///")

	newStore, err = store.Open(filename)
	if err != nil {
		return
	}

	if md, ok := newStore.(store.MetaSaver); ok {
		data := map[string]string{
			"Name":        content.Meta.Name,
			"Source":      content.Meta.Source,
			"Description": content.Meta.Description,
			"Version":     content.Meta.Version,
			"Type":        content.Meta.Type,
		}
		md.SetMetaData(data)
	}

	for prefix, objs := range content.Sections {
		var sub store.Store
		sub, err = newStore.MakeSub(prefix)
		if err != nil {
			return
		}

		for k, obj := range objs {
			err = sub.Save(k, obj)
			if err != nil {
				return
			}
		}
	}

	return
}

func forceParamRemoval(d *DataStack, l store.Store) error {
	toRemove := [][]string{}
	layer0 := d.Layers()[0]
	lSubs := l.Subs()
	dSubs := layer0.Subs()
	for k, v := range lSubs {
		dSub := dSubs[k]
		if dSub == nil {
			continue
		}
		lKeys, _ := v.Keys()
		for _, key := range lKeys {
			var dItem interface{}
			var lItem interface{}
			if err := dSub.Load(key, &dItem); err != nil {
				continue
			}
			if err := v.Load(key, &lItem); err != nil {
				return err
			}
			toRemove = append(toRemove, []string{k, key})
		}
	}
	for _, item := range toRemove {
		dSub := d.Subs()[item[0]]
		dSub.Remove(item[1])
	}
	return nil
}

// Try to add to available - Must lock before calling
func (pc *PluginController) importPluginProvider(rt *backend.RequestTracker, provider string) error {
	pc.Infof("Importing plugin provider: %s\n", provider)

	cmd := exec.Command(pc.pluginDir+"/"+provider, "define")

	// Setup env vars to run plugin - auth should be parameters.
	claims := backend.NewClaim(provider, "system", time.Hour*1).
		AddRawClaim("*", "*", "*").
		AddSecrets("", "", "")
	token, _ := rt.SealClaims(claims)
	apiURL := rt.ApiURL(net.ParseIP("0.0.0.0"))
	staticURL := rt.FileURL(net.ParseIP("0.0.0.0"))

	env := os.Environ()
	env = append(env, fmt.Sprintf("RS_ENDPOINT=%s", apiURL))
	env = append(env, fmt.Sprintf("RS_FILESERVER=%s", staticURL))
	env = append(env, fmt.Sprintf("RS_TOKEN=%s", token))
	cmd.Env = env

	out, err := cmd.CombinedOutput()
	if err != nil {
		pc.Errorf("Skipping %s because %s: %s\n", provider, err, string(out))
		return fmt.Errorf("Skipping %s because %s: %s\n", provider, err, string(out))
	}
	pp := &models.PluginProvider{}
	err = json.Unmarshal(out, pp)
	if err != nil {
		pc.Errorf("Skipping %s because of bad json: %s\n%s\n", provider, err, out)
		return fmt.Errorf("Skipping %s because of bad json: %s\n%s\n", provider, err, out)
	}
	skip := false
	pp.Fill()

	if pp.PluginVersion != 2 {
		pc.Errorf("Skipping %s because of bad version: %d\n", provider, pp.PluginVersion)
		return fmt.Errorf("Skipping %s because of bad version: %d\n", provider, pp.PluginVersion)
	}

	content := &models.Content{}
	content.Fill()

	if pp.Content != "" {
		codec := store.YamlCodec
		if err := codec.Decode([]byte(pp.Content), content); err != nil {
			return err
		}
	}
	cName := pp.Name
	content.Meta.Name = cName

	if content.Meta.Version == "" || content.Meta.Version == "Unspecified" {
		content.Meta.Version = pp.Version
	}
	if content.Meta.Description == "" {
		content.Meta.Description = fmt.Sprintf("Content layer for %s plugin provider", pp.Name)
	}
	if content.Meta.Source == "" {
		content.Meta.Source = "FromPluginProvider"
	}
	content.Meta.Type = "plugin"

	if skip {
		return nil
	}
	pc.Tracef("Building new datastore for: %s\n", provider)
	ns, err := pc.buildNewStore(content)
	if err != nil {
		pc.Errorf("Skipping %s because of bad store: %v\n", pp.Name, err)
		return err
	}
	pc.Tracef("Replacing new datastore for: %s\n", provider)
	rt.AllLocked(func(d backend.Stores) {
		l := rt.Logger.Level()
		rt.Logger.SetLevel(logger.Error)
		defer rt.Logger.SetLevel(l)

		ds := pc.dt.Backend.(*DataStack)
		nbs, hard, _ := ds.AddReplacePluginLayer(cName, ns, pc.dt.Secrets, pc.dt.Logger, forceParamRemoval)
		if hard != nil {
			rt.Errorf("Skipping %s because of bad store errors: %v\n", pp.Name, hard)
			err = hard
			return
		}
		pc.dt.ReplaceBackend(rt, nbs)
	})
	pc.Tracef("Completed replacing new datastore for: %s\n", provider)
	if err != nil {
		return err
	}

	if _, ok := pc.AvailableProviders[pp.Name]; !ok {
		pc.Infof("Adding plugin provider: %s\n", pp.Name)
		pp.Fill()
		pc.AvailableProviders[pp.Name] = pp
		for _, aa := range pp.AvailableActions {
			aa.Provider = pp.Name
		}
		out, err = exec.Command(
			path.Join(pc.pluginDir, provider),
			"unpack",
			path.Join(pc.dt.FileRoot, "files", "plugin_providers", pp.Name)).CombinedOutput()
		if err != nil {
			pc.Errorf("Unpack for %s failed: %v", pp.Name, err)
			pc.Errorf("%s", out)
		}
		rt.Publish("plugin_providers", "create", pp.Name, pp)
		return nil
	} else {
		pc.Infof("Already exists plugin provider: %s\n", pp.Name)
	}
	return nil
}

// Try to stop using plugins and remove available - Must lock controller lock before calling
func (pc *PluginController) removePluginProvider(rt *backend.RequestTracker, provider string) error {
	pc.Tracef("removePluginProvider Started: %s\n", provider)
	var name string
	for _, pp := range pc.AvailableProviders {
		if provider == pp.Name {
			name = pp.Name
			break
		}
	}
	if name != "" {
		pc.Infof("Removing plugin provider: %s\n", name)
		rt.Publish("plugin_providers", "delete", name, pc.AvailableProviders[name])

		// Remove the plugin content
		rt.AllLocked(func(d backend.Stores) {
			ds := pc.dt.Backend.(*DataStack)
			nbs, hard, _ := ds.RemovePluginLayer(name, pc.dt.Logger, pc.dt.Secrets)
			if hard != nil {
				rt.Errorf("Skipping removal of plugin content layer %s because of bad store errors: %v\n", name, hard)
			} else {
				pc.dt.ReplaceBackend(rt, nbs)
			}
		})
		delete(pc.AvailableProviders, name)
	}

	pc.Tracef("removePluginProvider Finished: %s\n", provider)
	return nil
}

func (pc *PluginController) UploadPluginProvider(c *gin.Context, fileRoot, name string) (*models.PluginProviderUploadInfo, *models.Error) {
	if err := os.MkdirAll(path.Join(fileRoot, `plugins`), 0755); err != nil {
		pc.Errorf("Unable to create plugins directory: %v", err)
		return nil, models.NewError("API_ERROR", http.StatusConflict,
			fmt.Sprintf("upload: unable to create plugins directory"))
	}
	var copied int64
	ctype := c.Request.Header.Get(`Content-Type`)
	switch strings.Split(ctype, "; ")[0] {
	case `application/octet-stream`:
		if c.Request.Body == nil {
			return nil, models.NewError("API ERROR", http.StatusBadRequest,
				fmt.Sprintf("upload: Unable to upload %s: missing body", name))
		}
	case `multipart/form-data`:
		header, err := c.FormFile("file")
		if err != nil {
			return nil, models.NewError("API ERROR", http.StatusBadRequest,
				fmt.Sprintf("upload: Failed to find multipart file: %v", err))
		}
		name = path.Base(header.Filename)
	default:
		return nil, models.NewError("API ERROR", http.StatusUnsupportedMediaType,
			fmt.Sprintf("upload: plugin_provider %s content-type %s is not application/octet-stream or multipart/form-data", name, ctype))
	}

	ppTmpName := path.Join(pc.pluginDir, fmt.Sprintf(`.%s.part`, path.Base(name)))
	ppName := path.Join(pc.pluginDir, path.Base(name))
	if _, err := os.Open(ppTmpName); err == nil {
		return nil, models.NewError("API ERROR", http.StatusConflict,
			fmt.Sprintf("upload: plugin_provider %s already uploading", name))
	}
	tgt, err := os.Create(ppTmpName)
	defer tgt.Close()
	if err != nil {
		return nil, models.NewError("API ERROR", http.StatusConflict,
			fmt.Sprintf("upload: Unable to upload %s: %v", name, err))
	}

	switch strings.Split(ctype, "; ")[0] {
	case `application/octet-stream`:
		copied, err = io.Copy(tgt, c.Request.Body)
		if err != nil {
			os.Remove(ppTmpName)
			return nil, models.NewError("API ERROR", http.StatusInsufficientStorage,
				fmt.Sprintf("upload: Failed to upload %s: %v", name, err))
		}
		if c.Request.ContentLength > 0 && copied != c.Request.ContentLength {
			os.Remove(ppTmpName)
			return nil, models.NewError("API ERROR", http.StatusBadRequest,
				fmt.Sprintf("upload: Failed to upload entire file %s: %d bytes expected, %d bytes received", name, c.Request.ContentLength, copied))
		}
	case `multipart/form-data`:
		header, _ := c.FormFile("file")
		file, _ := header.Open()
		defer file.Close()
		copied, err = io.Copy(tgt, file)
		if err != nil {
			return nil, models.NewError("API ERROR", http.StatusBadRequest,
				fmt.Sprintf("upload: iso %s could not save", header.Filename))
		}
		file.Close()
	}
	tgt.Close()

	os.Remove(ppName)
	os.Rename(ppTmpName, ppName)
	os.Chmod(ppName, 0700)

	pc.lock.Lock()
	defer pc.lock.Unlock()
	// If it is here, remove it.
	rt := pc.Request()
	pc.removePluginProvider(rt, name)

	var berr *models.Error
	err = pc.importPluginProvider(rt, name)
	if err != nil {
		berr = models.NewError("API ERROR", http.StatusBadRequest,
			fmt.Sprintf("Import plugin failed %s: %v", name, err))
	}
	return &models.PluginProviderUploadInfo{Path: name, Size: copied}, berr
}

func (pc *PluginController) RemovePluginProvider(name string) error {
	pluginProviderName := path.Join(pc.pluginDir, path.Base(name))
	if err := os.Remove(pluginProviderName); err != nil {
		return err
	}
	pc.lock.Lock()
	defer pc.lock.Unlock()
	rt := pc.Request()
	return pc.removePluginProvider(rt, name)
}

// Get the socketId
func (pc *PluginController) getSocketId(name string) int64 {
	pc.lock.Lock()
	defer pc.lock.Unlock()

	rp, ok := pc.runningPlugins[name]
	if !ok || rp.Client == nil {
		return 0
	}
	return rp.Client.socketId
}
