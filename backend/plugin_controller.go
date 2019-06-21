package backend

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
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/provision/store"
	"github.com/gin-gonic/gin"
)

type PluginController struct {
	logger.Logger
	lock               *sync.Mutex
	AvailableProviders map[string]*models.PluginProvider
	runningPlugins     map[string]*RunningPlugin
	dt                 *DataTracker
	pluginDir          string
	pluginCommDir      string
	done               chan bool
	finished           chan bool
	events             chan *models.Event
	publishers         *Publishers
	actions            *actions
	AddStorageType     func(string)
}

func (pc *PluginController) Request(locks ...string) *RequestTracker {
	res := pc.dt.Request(pc.Logger, locks...)
	return res
}

func (pc *PluginController) SetLevel(lvl logger.Level) {
	pc.lock.Lock()
	defer pc.lock.Unlock()
	pc.Logger = pc.Logger.SetLevel(lvl)
}

/*
 * Create controller and start an event listener.
 */
func InitPluginController(pluginDir, pluginCommDir string, l logger.Logger) (pc *PluginController, err error) {
	err = os.MkdirAll(pluginCommDir, 0755)
	if err != nil {
		return
	}
	l.Debugf("Creating Plugin Controller\n")
	pc = &PluginController{
		Logger:             l.Switch("plugin"),
		pluginDir:          pluginDir,
		pluginCommDir:      pluginCommDir,
		AvailableProviders: make(map[string]*models.PluginProvider, 0),
		runningPlugins:     make(map[string]*RunningPlugin, 0),
		lock:               &sync.Mutex{},
	}
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

func (pc *PluginController) definePluginProvider(rt *RequestTracker, provider, contentDir string) (*models.PluginProvider, error) {
	pc.Infof("Importing plugin provider: %s\n", provider)
	cmd := exec.Command(provider, "define")

	// Setup env vars to run plugin - auth should be parameters.
	claims := NewClaim(provider, "system", time.Hour*1).
		AddRawClaim("*", "get", "*").
		AddSecrets("", "", "")
	token, _ := rt.SealClaims(claims)
	apiURL := rt.ApiURL(net.ParseIP("127.0.0.1"))
	staticURL := rt.FileURL(net.ParseIP("127.0.0.1"))

	env := os.Environ()
	env = append(env, fmt.Sprintf("RS_ENDPOINT=%s", apiURL))
	env = append(env, fmt.Sprintf("RS_FILESERVER=%s", staticURL))
	env = append(env, fmt.Sprintf("RS_TOKEN=%s", token))
	env = append(env, fmt.Sprintf("RS_WEBROOT=%s", rt.FileRoot()))
	cmd.Env = env

	out, err := cmd.CombinedOutput()
	if err != nil {
		pc.Errorf("Skipping %s because %s: %s\n", provider, err, string(out))
		return nil, fmt.Errorf("Skipping %s because %s: %s\n", provider, err, string(out))
	}
	pp := &models.PluginProvider{}
	err = json.Unmarshal(out, pp)
	if err != nil {
		pc.Errorf("Skipping %s because of bad json: %s\n%s\n", provider, err, out)
		return nil, fmt.Errorf("Skipping %s because of bad json: %s\n%s\n", provider, err, out)
	}
	pp.Fill()

	if pp.PluginVersion != 2 {
		pc.Errorf("Skipping %s because of bad version: %d\n", provider, pp.PluginVersion)
		return nil, fmt.Errorf("Skipping %s because of bad version: %d\n", provider, pp.PluginVersion)
	}
	for _, aa := range pp.AvailableActions {
		aa.Provider = pp.Name
	}
	out, err = exec.Command(
		path.Join(provider),
		"unpack",
		path.Join(contentDir, "files", "plugin_providers", pp.Name)).CombinedOutput()
	if err != nil {
		pc.Errorf("Unpack for %s failed: %v", pp.Name, err)
		pc.Errorf("%s", out)
		return nil, fmt.Errorf("Unpack for %s failed: %v %s", pp.Name, err, string(out))
	}
	return pp, nil
}

func (pc *PluginController) define(rt *RequestTracker, contentDir string) (map[string]*models.PluginProvider, error) {
	providers := map[string]*models.PluginProvider{}
	files, err := ioutil.ReadDir(pc.pluginDir)
	if err != nil {
		pc.Tracef("PluginController Define: finished ReadDir error: %v\n", err)
		return providers, err
	}
	for _, f := range files {
		pc.Debugf("PluginController Define: getting definition for %s\n", f.Name())
		pp, perr := pc.definePluginProvider(rt, path.Join(pc.pluginDir, f.Name()), contentDir)
		if perr == nil {
			providers[pp.Name] = pp
		}
		// Skip erroring plugins for now
	}
	return providers, nil
}

func (pc *PluginController) Define(rt *RequestTracker, contentDir string) (map[string]*models.PluginProvider, error) {
	pc.lock.Lock()
	defer pc.lock.Unlock()
	return pc.define(rt, contentDir)
}

func (pc *PluginController) Start(
	dt *DataTracker,
	providers map[string]*models.PluginProvider,
	pubs *Publishers) {
	pc.actions = newActions()
	pc.publishers = pubs
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
	pc.Debugf("Starting Plugin Controller:\n")
	pc.StartPlugins(dt, providers)
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
	case "contents":
		if e.Key == "rackn-license" {
			pc.NoPublish().Tracef("PluginController Publish Event license started: %v\n", e)
			pc.events <- e
			pc.NoPublish().Tracef("PluginController Publish Event license finished: %v\n", e)
		}
	case "plugins", "plugin", "plugin_provider", "plugin_providers":
		pc.NoPublish().Tracef("PluginController Publish Event started: %v\n", e)
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

func forceParamRemoval(d *DataStack, l store.Store, logger logger.Logger) error {
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

// Try to stop using plugins and remove available - Must lock controller lock before calling
func (pc *PluginController) removePluginProvider(rt *RequestTracker, provider string) error {
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
		rt.AllLocked(func(d Stores) {
			ds := pc.dt.Backend
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
	if _, err := os.Open(ppTmpName); err == nil {
		return nil, models.NewError("API ERROR", http.StatusConflict,
			fmt.Sprintf("upload: plugin_provider %s already uploading", name))
	}
	tgt, err := os.Create(ppTmpName)
	defer tgt.Close()
	defer os.Remove(ppTmpName)
	if err != nil {
		return nil, models.NewError("API ERROR", http.StatusConflict,
			fmt.Sprintf("upload: Unable to upload %s: %v", name, err))
	}

	switch strings.Split(ctype, "; ")[0] {
	case `application/octet-stream`:
		copied, err = io.Copy(tgt, c.Request.Body)
		if err != nil {
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
				fmt.Sprintf("upload: plugin provider %s could not save", header.Filename))
		}
		file.Close()
	}
	tgt.Close()
	os.Chmod(ppTmpName, 0700)
	pc.lock.Lock()
	defer pc.lock.Unlock()
	// If it is here, remove it.
	rt := pc.Request()
	pp, perr := pc.definePluginProvider(rt, ppTmpName, pc.dt.FileRoot)
	if perr != nil {
		return nil, models.NewError("API ERROR", http.StatusBadRequest,
			fmt.Sprintf("Import plugin failed %s: define failed: %v", name, perr))
	}
	ns, err := pp.Store()
	if err != nil {
		return nil, models.NewError("API ERROR", http.StatusBadRequest,
			fmt.Sprintf("Import plugin failed %s: bad store: %v", name, err))
	}
	rt.AllLocked(func(d Stores) {
		ds := pc.dt.Backend
		nbs, hard, _ := ds.AddReplacePluginLayer(name, ns, pc.dt.Secrets, pc.dt.Logger, forceParamRemoval)
		if hard != nil {
			rt.Errorf("Skipping %s because of bad store errors: %v\n", pp.Name, hard)
			err = hard
			return
		}
		pc.dt.ReplaceBackend(rt, nbs)
	})
	if err != nil {
		return nil, models.NewError("API ERROR", http.StatusBadRequest,
			fmt.Sprintf("Import plugin failed %s: bad plugin: %v", name, err))
	}
	ppName := path.Join(pc.pluginDir, pp.Name)
	os.Remove(ppName)
	os.Rename(ppTmpName, ppName)
	pc.AvailableProviders[pp.Name] = pp
	pc.allPlugins(pp.Name, "stop")
	pc.allPlugins(pp.Name, "start")
	return &models.PluginProviderUploadInfo{Path: pp.Name, Size: copied}, nil
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
