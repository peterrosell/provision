package backend

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/template"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/digitalrebar/logger"
	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/provision/store"
)

type followUpSaver interface {
	followUpSave()
}

type followUpDeleter interface {
	followUpDelete()
}

type AuthSaver interface {
	AuthKey() string
}

// dtobjs is an in-memory cache of all the objects we could
// reference. The implementation of this may need to change from
// storing a slice of things to a more elaborate datastructure at some
// point in time.  Since that point in time is when the slices are
// forced out of CPU cache, I am not terribly concerned for now.
// Until that point is reached, sorting and searching slices is
// fantastically efficient.
type Store struct {
	sync.RWMutex
	index.Index
	backingStore store.Store
}

func (s *Store) getBackend(obj models.Model) store.Store {
	return s.backingStore
}

type dtSetter interface {
	models.Model
	setDT(*DataTracker)
}

func Fill(t store.KeySaver) {
	switch obj := t.(type) {
	case *Stage:
		if obj.Stage == nil {
			obj.Stage = &models.Stage{}
		}
	case *BootEnv:
		if obj.BootEnv == nil {
			obj.BootEnv = &models.BootEnv{}
		}
	case *Job:
		if obj.Job == nil {
			obj.Job = &models.Job{}
		}
	case *Lease:
		if obj.Lease == nil {
			obj.Lease = &models.Lease{}
		}
	case *Machine:
		if obj.Machine == nil {
			obj.Machine = &models.Machine{}
		}
	case *Param:
		if obj.Param == nil {
			obj.Param = &models.Param{}
		}
	case *Plugin:
		if obj.Plugin == nil {
			obj.Plugin = &models.Plugin{}
		}
	case *Pref:
		if obj.Pref == nil {
			obj.Pref = &models.Pref{}
		}
	case *Profile:
		if obj.Profile == nil {
			obj.Profile = &models.Profile{}
		}
	case *Reservation:
		if obj.Reservation == nil {
			obj.Reservation = &models.Reservation{}
		}
	case *Subnet:
		if obj.Subnet == nil {
			obj.Subnet = &models.Subnet{}
		}
	case *Task:
		if obj.Task == nil {
			obj.Task = &models.Task{}
		}
	case *Template:
		if obj.Template == nil {
			obj.Template = &models.Template{}
		}
	case *User:
		if obj.User == nil {
			obj.User = &models.User{}
		}
	case *Workflow:
		if obj.Workflow == nil {
			obj.Workflow = &models.Workflow{}
		}
	case *Role:
		if obj.Role == nil {
			obj.Role = &models.Role{}
		}
	case *Tenant:
		if obj.Tenant == nil {
			obj.Tenant = &models.Tenant{}
		}
	case *RawModel:
		if obj.RawModel == nil {
			obj.RawModel = &models.RawModel{}
		}
	default:
		panic(fmt.Sprintf("Unknown backend model %T", t))
	}
}

func ModelToBackend(m models.Model) store.KeySaver {
	switch obj := m.(type) {
	case store.KeySaver:
		return obj
	case *models.Stage:
		return &Stage{Stage: obj}
	case *models.BootEnv:
		return &BootEnv{BootEnv: obj}
	case *models.Job:
		return &Job{Job: obj}
	case *models.Lease:
		return &Lease{Lease: obj}
	case *models.Machine:
		return &Machine{Machine: obj}
	case *models.Param:
		return &Param{Param: obj}
	case *models.Plugin:
		return &Plugin{Plugin: obj}
	case *models.Pref:
		return &Pref{Pref: obj}
	case *models.Profile:
		return &Profile{Profile: obj}
	case *models.Reservation:
		return &Reservation{Reservation: obj}
	case *models.Subnet:
		return &Subnet{Subnet: obj}
	case *models.Task:
		return &Task{Task: obj}
	case *models.Template:
		return &Template{Template: obj}
	case *models.User:
		return &User{User: obj}
	case *models.Workflow:
		return &Workflow{Workflow: obj}
	case *models.Role:
		return &Role{Role: obj}
	case *models.Tenant:
		return &Tenant{Tenant: obj}
	case *models.RawModel:
		return &RawModel{RawModel: obj}
	default:
		return nil
	}
}

func toBackend(m models.Model, rt *RequestTracker) store.KeySaver {
	if res, ok := m.(store.KeySaver); ok {
		if v, ok := res.(validator); ok {
			v.setRT(rt)
		}
		return res
	}
	var ours store.KeySaver
	if rt != nil {
		backend := rt.stores(m.Prefix())
		if backend == nil {
			rt.Panicf("No store for %T", m)
		}
		k := m.Key()
		if k != "" {
			if this := backend.Find(k); this != nil {
				ours = this.(store.KeySaver)
			}
		}
	}

	switch obj := m.(type) {
	case *models.Stage:
		var res Stage
		if ours != nil {
			res = *ours.(*Stage)
		} else {
			res = Stage{}
		}
		res.Stage = obj
		res.rt = rt
		return &res
	case *models.BootEnv:
		var res BootEnv
		if ours != nil {
			res = *ours.(*BootEnv)
		} else {
			res = BootEnv{}
		}
		res.BootEnv = obj
		res.rt = rt
		return &res
	case *models.Job:
		var res Job
		if ours != nil {
			res = *ours.(*Job)
		} else {
			res = Job{}
		}
		res.Job = obj
		res.rt = rt
		return &res
	case *models.Lease:
		var res Lease
		if ours != nil {
			res = *ours.(*Lease)
		} else {
			res = Lease{}
		}
		res.Lease = obj
		res.rt = rt
		return &res
	case *models.Machine:
		var res Machine
		if ours != nil {
			res = *ours.(*Machine)
		} else {
			res = Machine{}
		}
		res.Machine = obj
		res.rt = rt
		return &res
	case *models.Param:
		var res Param
		if ours != nil {
			res = *ours.(*Param)
		} else {
			res = Param{}
		}
		res.Param = obj
		res.rt = rt
		return &res
	case *models.Plugin:
		var res Plugin
		if ours != nil {
			res = *ours.(*Plugin)
		} else {
			res = Plugin{}
		}
		res.Plugin = obj
		res.rt = rt
		return &res
	case *models.Pref:
		var res Pref
		if ours != nil {
			res = *ours.(*Pref)
		} else {
			res = Pref{}
		}
		res.Pref = obj
		res.rt = rt
		return &res
	case *models.Profile:
		var res Profile
		if ours != nil {
			res = *ours.(*Profile)
		} else {
			res = Profile{}
		}
		res.Profile = obj
		res.rt = rt
		return &res
	case *models.Reservation:
		var res Reservation
		if ours != nil {
			res = *ours.(*Reservation)
		} else {
			res = Reservation{}
		}
		res.Reservation = obj
		res.rt = rt
		return &res
	case *models.Subnet:
		var res Subnet
		if ours != nil {
			res = *ours.(*Subnet)
		} else {
			res = Subnet{}
		}
		res.Subnet = obj
		res.rt = rt
		return &res
	case *models.Task:
		var res Task
		if ours != nil {
			res = *ours.(*Task)
		} else {
			res = Task{}
		}
		res.Task = obj
		res.rt = rt
		return &res
	case *models.Template:
		var res Template
		if ours != nil {
			res = *ours.(*Template)
		} else {
			res = Template{}
		}
		res.Template = obj
		res.rt = rt
		return &res

	case *models.User:
		var res User
		if ours != nil {
			res = *ours.(*User)
		} else {
			res = User{}
		}
		res.User = obj
		res.rt = rt
		return &res
	case *models.Workflow:
		var res Workflow
		if ours != nil {
			res = *ours.(*Workflow)
		} else {
			res = Workflow{}
		}
		res.Workflow = obj
		res.rt = rt
		return &res
	case *models.Role:
		var res Role
		if ours != nil {
			res = *ours.(*Role)
		} else {
			res = Role{}
		}
		res.Role = obj
		res.rt = rt
		return &res
	case *models.Tenant:
		var res Tenant
		if ours != nil {
			res = *ours.(*Tenant)
		} else {
			res = Tenant{}
		}
		res.Tenant = obj
		res.rt = rt
		return &res
	case *models.RawModel:
		var res RawModel
		if ours != nil {
			res = *ours.(*RawModel)
		} else {
			res = RawModel{}
		}
		res.RawModel = obj
		res.rt = rt
		return &res

	default:
		log.Panicf("Unknown model %T", m)
	}
	return nil
}

func (p *DataTracker) logCheck(prefName, prefVal string) (logName, logTarget string, lvl logger.Level, err error) {
	logName = "default"
	logTarget = "warn"
	lvl = logger.Warn

	switch prefVal {
	case "trace", "debug", "info", "warn", "error", "panic", "fatal":
		logTarget = prefVal
	case "0":
		logTarget = "warn"
	case "1":
		logTarget = "info"
	case "2":
		logTarget = "debug"
	default:
		err = fmt.Errorf("Invalid log value %s for %s,  Ignoring change", prefVal, prefName)
		return
	}
	if logTarget != prefVal {
		p.Logger.Errorf("Pref %s log level %s is obsolete.  Please migrate to using %s",
			prefName, prefVal, logTarget)
	}
	switch prefName {
	case "debugDhcp":
		logName = "dhcp"
	case "debugRenderer":
		logName = "render"
	case "debugBootEnv":
		logName = "bootenv"
	case "debugFrontend":
		logName = "frontend"
	case "debugPlugins":
		logName = "plugin"
	case "logLevel":
		logName = "default"
	default:
		err = fmt.Errorf("Invalid logging preference %s, ignoring change", prefName)
		return
	}
	lvl, err = logger.ParseLevel(logTarget)
	return
}

// DataTracker represents everything there is to know about acting as
// a dataTracker.
type DataTracker struct {
	logger.Logger
	FileRoot            string
	LogRoot             string
	OurAddress          string
	ForceOurAddress     bool
	Cleanup             bool
	StaticPort, ApiPort int
	DrpId               string
	FS                  *FileSystem
	Backend             *DataStack
	Secrets             store.Store
	secretsMux          *sync.Mutex
	objs                map[string]*Store
	defaultPrefs        map[string]string
	runningPrefs        map[string]string
	prefMux             *sync.Mutex
	allMux              *sync.RWMutex
	GlobalProfileName   string
	tokenManager        *JwtManager
	rootTemplate        *template.Template
	tmplMux             *sync.Mutex
	thunks              []func()
	thunkMux            *sync.Mutex
	publishers          *Publishers
	macAddrMap          map[string]string
	macAddrMux          *sync.RWMutex
	licenses            models.LicenseBundle
	pc                  *PluginController
}

func (p *DataTracker) LogFor(s string) logger.Logger {
	return p.Logger.Buffer().Log(s)
}

func (dt *DataTracker) reportPath(s string) string {
	return strings.TrimPrefix(s, dt.FileRoot)
}

type Stores func(string) *Store

func allKeySavers() []models.Model {
	return []models.Model{
		&Role{},
		&Pref{},
		&Param{},
		&User{},
		&Template{},
		&Task{},
		&Profile{},
		&BootEnv{},
		&Stage{},
		&Workflow{},
		&Machine{},
		&Subnet{},
		&Reservation{},
		&Lease{},
		&Plugin{},
		&Job{},
		&Tenant{},
	}
}

func (p *DataTracker) LocalIP(remote net.IP) string {
	// If we are behind a NAT, always use Our Address
	if p.ForceOurAddress && p.OurAddress != "" {
		p.Debugf("addrCache: Forced to use static address %s", p.OurAddress)
		return p.OurAddress
	}
	if localIP := LocalFor(p.Logger, remote); localIP != nil {
		return localIP.String()
	}
	// Determining what this is needs to be made smarter, probably by
	// firguing out which interface the default route goes over for ipv4
	// then ipv6, and then figurig out the appropriate address on that
	// interface
	if p.OurAddress != "" {
		return p.OurAddress
	}
	gwIp := DefaultIP(p.Logger)
	if gwIp == nil {
		p.Warnf("Failed to find appropriate local IP to use for %s", remote)
		p.Warnf("No --static-ip and no default gateway to use in its place")
		p.Warnf("Please set --static-ip ")
		return ""
	}
	p.Infof("Falling back to local address %s as default target for remote %s", gwIp, remote)
	return gwIp.String()
}

func (p *DataTracker) regenSecureParams(
	rt *RequestTracker,
	paramer models.Paramer,
	hard, soft *models.Error) models.Paramer {
	params := paramer.GetParams()
	pubkey, err := rt.PublicKeyFor(paramer)
	if err != nil {
		hard.Errorf("Error getting public key for %s:%s: %v", paramer.Prefix(), paramer.Key(), err)
		return nil
	}
	secureParams := map[string]interface{}{}
	for k, v := range params {
		pThing := rt.Find("params", k)
		if pThing == nil {
			continue
		}
		param := AsParam(pThing)
		if !param.Secure {
			continue
		}
		secureV := &models.SecureData{}
		if err := models.Remarshal(v, secureV); err == nil {
			continue
		}
		if err := secureV.Marshal(pubkey, v); err != nil {
			hard.Errorf("Error marshalling secure data: %v", err)
			continue
		}
		p.Infof("Securing param %s on %s:%s", k, paramer.Prefix(), paramer.Key())
		secureParams[k] = secureV
	}
	if len(secureParams) == 0 {
		return nil
	}
	for k, v := range secureParams {
		params[k] = v
	}
	paramer.SetParams(params)
	return paramer
}

func (p *DataTracker) reportErrors(prefix string, obj models.Model, hard *models.Error) {
	layers := p.Backend.Layers()
	for idx, layerName := range p.Backend.LayerIndex {
		layer := layers[idx]
		bk := layer.GetSub(prefix)
		if bk == nil {
			continue
		}
		storeKeys, err := bk.Keys()
		if err != nil {
			hard.Errorf("Error fetching keys for %s: %v", prefix, err)
			hard.Errorf("This is likely not recoverable, and you should restore from backup.")
			continue
		}
		sort.Strings(storeKeys)
		for _, key := range storeKeys {
			err := bk.Load(key, obj)
			if err == nil {
				continue
			}
			if p.Cleanup && idx == 0 {
				hard.Errorf("Removing corrupt item %s:%s", prefix, key)
				bk.Remove(key)
				continue
			}
			hard.Errorf("Store %s item %s failed to load from layer %s: %v", prefix, key, layerName, err)
			if idx == 0 {
				hard.Errorf("Passing --cleanup as a start option to dr-provision will delete the corrupt item")
			} else if strings.HasPrefix(layerName, "content-") {
				hard.Errorf("Try manually replacing content layer %s", strings.TrimPrefix(layerName, "content-"))
			} else if strings.HasPrefix(layerName, "plugin-") {
				hard.Errorf("Try manually replacing plugin %s", strings.TrimPrefix(layerName, "plugin-"))
			} else {
				hard.Errorf("Corrupt item is in %s", layerName)
			}
		}
	}
}

func (p *DataTracker) rebuildCache(loadRT *RequestTracker) (hard, soft *models.Error) {
	hard = &models.Error{Code: 500, Type: "Failed to load backing objects from cache"}
	soft = &models.Error{Code: 422, Type: ValidationError}
	toSave := []store.KeySaver{}
	p.objs = map[string]*Store{}
	objs := allKeySavers()
	// First pass -- just load the objects without validating them
	for _, obj := range objs {
		prefix := obj.Prefix()
		bk := p.Backend.GetSub(prefix)
		p.objs[prefix] = &Store{backingStore: bk}
		keys, err := bk.Keys()
		res := make([]models.Model, len(keys))
		if err == nil {
			tmpl := obj.(store.KeySaver)
			for i := range keys {
				v := toBackend(tmpl.New(), loadRT)
				if err = bk.Load(keys[i], v); err != nil {
					p.reportErrors(prefix, v, hard)
				}
				res[i] = v
			}
		} else {
			p.reportErrors(prefix, obj, hard)
		}
		p.objs[prefix].Index = *index.Create(res)
	}
	if hard.ContainsError() {
		return
	}
	// Second pass -- now that everything is loaded, validate them all.
	for _, obj := range objs {
		prefix := obj.Prefix()
		bk := p.Backend.GetSub(prefix)
		res := loadRT.stores(prefix).Items()
		for i := range res {
			if v, ok := res[i].(validator); ok {
				v.setRT(loadRT)
			}
			if v, ok := res[i].(models.Paramer); ok {
				ts := p.regenSecureParams(loadRT, v, hard, soft)
				if ts != nil {
					toSave = append(toSave, ts.(store.KeySaver))
				}
			}
			if prefix == "leases" {
				lease := AsLease(res[i])
				if lease.State == "PROBE" {
					lease.Invalidate()
				}
			}
			if v, ok := res[i].(store.LoadHooker); ok {
				v.OnLoad()
			}
			if v, ok := res[i].(models.Validator); ok {
				if !v.Useable() {
					hard.AddError(v.HasError())
				} else {
					soft.AddError(v.HasError())
				}
			}
		}
		if prefix == "tasks" {
			stack, ok := bk.(*store.StackedStore)
			if ok {
				subStore := stack.Subs()[prefix]
				if subStore != nil {
					sub := stack.Subs()[prefix].(*store.StackedStore)
					for i := range res {
						obj := AsTask(res[i])
						key := obj.Key()
						meta := sub.MetaFor(key)
						if flagStr, ok := meta["feature-flags"]; ok && len(flagStr) > 0 {
							obj.MergeFeatures(strings.Split(flagStr, ","))
						}
						if obj.HasFeature("original-exit-codes") {
							obj.RemoveFeature("sane-exit-codes")
						}
						if !obj.HasFeature("original-exit-codes") {
							obj.AddFeature("sane-exit-codes")
						}
						res[i] = obj
					}
				}
			}
		}
		if prefix == "bootenvs" {
			for _, thing := range p.objs[prefix].Items() {
				benv := AsBootEnv(thing)
				benv.rt = loadRT
				benv.AddDynamicTree()
				benv.rt = nil
			}
		}

		if prefix == "templates" {
			buf := &bytes.Buffer{}
			for _, thing := range p.objs[prefix].Items() {
				tmpl := AsTemplate(thing)

				// This could be annoying performance wise because we double compile
				// all templates.  For now, we are ignoring the potential perf issue.
				_, err := template.New("").Funcs(models.DrpSafeFuncMap()).Parse(tmpl.Contents)
				if err != nil {
					hard.Errorf("Unable to load %s templates: %v", tmpl.ID, err)
				}
				fmt.Fprintf(buf, `{{define "%s"}}%s{{end}}`, tmpl.ID, tmpl.Contents)
			}
			if hard.ContainsError() {
				return
			}
			root, err := template.New("").Funcs(models.DrpSafeFuncMap()).Parse(buf.String())
			if err != nil {
				hard.Errorf("Unable to load root templates: %v", err)
				return
			}
			p.rootTemplate = root
			p.rootTemplate.Option("missingkey=error")
		}
	}
	for pre, s := range rawModelSchemaMap {
		if e := p.addStoreType(func(ref string) *Store { return p.objs[ref] }, pre, s, loadRT, soft); e != nil {
			soft.Errorf("Failed to reload %s: %v", pre, e)
		}
	}
	if !hard.ContainsError() {
		for _, item := range toSave {
			_, err := loadRT.Save(item)
			soft.AddError(err)
		}
	}
	p.loadLicense(loadRT)
	return
}

// GetObjectTypes returns a list of objects the backend is tracking.
func (p *DataTracker) GetObjectTypes() []string {
	sobjs := []string{}
	for _, obj := range allKeySavers() {
		sobjs = append(sobjs, obj.Prefix())
	}
	for pre := range rawModelSchemaMap {
		sobjs = append(sobjs, pre)
	}
	sort.Strings(sobjs)
	return sobjs
}

func (p *DataTracker) addStoreType(d Stores, prefix string, schema interface{}, rt *RequestTracker, soft *models.Error) error {
	_, berr := p.Backend.MakeSub(prefix)
	if berr != nil {
		return fmt.Errorf("dataTracker: Error creating substore %s: %v", prefix, berr)
	}
	// Record schema if specified for validation and indexes
	rawModelSchemaMap[prefix] = schema
	models.UpdateAllScopesWithRawModel(prefix)

	// Make sure that we rebuild the roles claims
	roles := d("roles")
	if roles != nil {
		for _, i := range roles.Items() {
			role := AsRole(i)
			role.ClearCachedClaims()
		}
	}

	bk := p.Backend.GetSub(prefix)
	p.objs[prefix] = &Store{backingStore: bk}
	m := &models.RawModel{"Type": prefix}
	storeObjs, serr := store.List(bk, toBackend(m, rt))
	if serr != nil {
		// Make fake index to keep others from failing and exploding.
		res := make([]models.Model, 0)
		p.objs[prefix].Index = *index.Create(res)
		return serr
	}
	res := make([]models.Model, len(storeObjs))
	for i := range storeObjs {
		res[i] = models.Model(storeObjs[i])
		if v, ok := res[i].(models.Validator); ok && v.Useable() {
			if soft != nil {
				soft.AddError(v.HasError())
			}
		}
	}
	p.objs[prefix].Index = *index.Create(res)
	return nil
}

func (p *DataTracker) AddStoreType(prefix string, schema interface{}) error {
	rt := p.Request(p.Logger)
	var err error
	rt.AllLocked(func(d Stores) {
		err = p.addStoreType(d, prefix, schema, rt, nil)
	})
	return err
}

// Create a new DataTracker that will use passed store to save all operational data
func NewDataTracker(backend *DataStack,
	secrets store.Store,
	fileRoot, logRoot, addr string, forceAddr bool,
	staticPort, apiPort int, drpId string,
	logger logger.Logger,
	defaultPrefs map[string]string,
	publishers *Publishers,
	pc *PluginController) *DataTracker {
	res := &DataTracker{
		Backend:           backend,
		Secrets:           secrets,
		FileRoot:          fileRoot,
		LogRoot:           logRoot,
		StaticPort:        staticPort,
		ApiPort:           apiPort,
		DrpId:             drpId,
		OurAddress:        addr,
		ForceOurAddress:   forceAddr,
		Logger:            logger,
		defaultPrefs:      defaultPrefs,
		runningPrefs:      map[string]string{},
		tokenManager:      NewJwtManager([]byte{}, JwtConfig{Method: jwt.SigningMethodHS256}),
		prefMux:           &sync.Mutex{},
		allMux:            &sync.RWMutex{},
		FS:                NewFS(fileRoot, logger),
		tmplMux:           &sync.Mutex{},
		GlobalProfileName: "global",
		thunks:            make([]func(), 0),
		thunkMux:          &sync.Mutex{},
		publishers:        publishers,
		macAddrMap:        map[string]string{},
		macAddrMux:        &sync.RWMutex{},
		secretsMux:        &sync.Mutex{},
		pc:                pc,
	}

	// Make sure incoming writable backend has all stores created
	loadRT := res.Request(logger)
	loadRT.AllLocked(func(d Stores) {
		objs := allKeySavers()
		for _, obj := range objs {
			prefix := obj.Prefix()
			_, err := backend.MakeSub(prefix)
			if err != nil {
				loadRT.Fatalf("dataTracker: Error creating substore %s: %v", prefix, err)
			}
		}
		// Load stores.
		hard, _ := res.rebuildCache(loadRT)
		if hard.HasError() != nil {
			loadRT.Fatalf("dataTracker: Error loading data: %v", hard.HasError())
		}
	})
	// Create minimal content.
	rt := res.Request(res.Logger,
		"stages:rw",
		"bootenvs:rw",
		"preferences:rw",
		"users:rw",
		"tenants:rw",
		"machines:rw",
		"profiles:rw",
		"params:rw",
		"workflows:rw",
		"roles:rw")
	rt.Do(func(d Stores) {
		// Load the prefs - overriding defaults.
		savePrefs := false
		for _, prefIsh := range d("preferences").Items() {
			pref := AsPref(prefIsh)
			res.runningPrefs[pref.Name] = pref.Val
		}

		// Set systemGrantorSecret and baseTokenSecret if unset and save it to backing store.
		prefs := res.Prefs()
		for _, pref := range []string{"systemGrantorSecret", "baseTokenSecret"} {
			if val, ok := prefs[pref]; !ok || val == "" {
				prefs[pref] = models.RandString(32)
				savePrefs = true
			}
		}
		// Migrate any number-based logging preferences
		for _, name := range []string{"debugDhcp",
			"debugRenderer",
			"debugBootEnv",
			"debugFrontend",
			"debugPlugins",
			"logLevel",
		} {
			val := prefs[name]
			if val == "" {
				val = "warn"
			}
			logName, logTarget, logLevel, lErr := res.logCheck(name, val)
			if lErr != nil {
				res.Logger.Fatalf("dataTracker: Invalid log level %v", lErr)
			}
			if val != logTarget {
				savePrefs = true
			}
			prefs[name] = logTarget
			// GREG: SetLevel in the logger codebase should track forks and update appropriately.
			res.LogFor(logName).SetLevel(logLevel)
		}
		if savePrefs {
			res.SetPrefs(rt, prefs)
		}
		res.tokenManager.updateKey([]byte(res.pref("baseTokenSecret")))

		if d("profiles").Find(res.GlobalProfileName) == nil {
			res.Infof("Creating %s profile", res.GlobalProfileName)
			rt.Create(&models.Profile{
				Name:        res.GlobalProfileName,
				Description: "Global profile attached automatically to all machines.",
				Params:      map[string]interface{}{},
				Meta: map[string]string{
					"icon":  "world",
					"color": "blue",
					"title": "Digital Rebar Provision",
				},
			})
		}
		users := d("users")
		if users.Count() == 0 {
			res.Infof("Creating rocketskates user")
			user := &User{}
			Fill(user)
			user.Name = "rocketskates"
			user.Roles = []string{"superuser"}
			if err := user.ChangePassword(rt, "r0cketsk8ts"); err != nil {
				logger.Fatalf("Failed to create rocketskates user: %v", err)
			}
			rt.Create(user)
		} else {
			user := rt.find("users", "rocketskates")
			if user != nil {
				u := AsUser(user)
				if u.Roles == nil || len(u.Roles) == 0 {
					u.Roles = []string{"superuser"}
					rt.Save(u)
				}
			}
		}
		machines := d("machines")
		for _, obj := range machines.Items() {
			machine := AsMachine(obj)
			bootEnv := d("bootenvs").Find(machine.BootEnv)
			if bootEnv == nil {
				continue
			}
			err := &models.Error{}
			AsBootEnv(bootEnv).render(rt, machine, err).register(rt)
			if err.ContainsError() {
				logger.Errorf("Error rendering machine %s at startup: %v", machine.UUID(), err)
			}
		}
		if err := res.RenderUnknown(rt); err != nil {
			logger.Fatalf("Failed to render unknown bootenv: %v", err)
		}
	})
	return res
}

func (p *DataTracker) Prefs() map[string]string {
	vals := map[string]string{}
	p.prefMux.Lock()
	for k, v := range p.defaultPrefs {
		vals[k] = v
	}
	for k, v := range p.runningPrefs {
		vals[k] = v
	}
	p.prefMux.Unlock()
	return vals
}

func (p *DataTracker) Pref(name string) (string, error) {
	res, ok := p.Prefs()[name]
	if !ok {
		return "", fmt.Errorf("No such preference %s", name)
	}
	return res, nil
}

func (p *DataTracker) pref(name string) string {
	return p.Prefs()[name]
}

func (p *DataTracker) SetPrefs(rt *RequestTracker, prefs map[string]string) error {
	err := &models.Error{}
	bootenvs := rt.d("bootenvs")
	stages := rt.d("stages")
	workflows := rt.d("workflows")
	lenCheck := func(name, val string) bool {
		if len(val) != 32 {
			err.Errorf("%s: Must be a string of length 32: %s", name, val)
			return false
		}
		return true
	}
	benvCheck := func(name, val string) *BootEnv {
		be := bootenvs.Find(val)
		if be == nil {
			err.Errorf("%s: Bootenv %s does not exist", name, val)
			return nil
		}
		return AsBootEnv(be)
	}
	stageCheck := func(name, val string) bool {
		stage := stages.Find(val)
		if stage == nil {
			err.Errorf("%s: Stage %s does not exist", name, val)
			return false
		}
		return true
	}
	workflowCheck := func(name, val string) bool {
		if val == "" {
			return true
		}
		if workflows.Find(val) == nil {
			err.Errorf("%s: Workflow %s does not exist", name, val)
			return false
		}
		return true
	}
	intCheck := func(name, val string) bool {
		_, e := strconv.Atoi(val)
		if e == nil {
			return true
		}
		err.Errorf("%s: %s", name, e.Error())
		return false
	}

	savePref := func(name, val string) bool {
		p.prefMux.Lock()
		defer p.prefMux.Unlock()
		pref := &models.Pref{}
		pref.Name = name
		pref.Val = val
		if _, saveErr := rt.Save(pref); saveErr != nil {
			err.Errorf("%s: Failed to save %s: %v", name, val, saveErr)
			return false
		}
		p.runningPrefs[name] = val
		return true
	}
	for name, val := range prefs {
		switch name {
		case "systemGrantorSecret":
			savePref(name, val)
		case "baseTokenSecret":
			if lenCheck(name, val) && savePref(name, val) {
				p.tokenManager.updateKey([]byte(val))
			}
		case "defaultBootEnv":
			be := benvCheck(name, val)
			if be != nil && !be.OnlyUnknown {
				savePref(name, val)
			}
		case "defaultStage":
			if stageCheck(name, val) {
				savePref(name, val)
			}
		case "defaultWorkflow":
			if workflowCheck(name, val) {
				savePref(name, val)
			}
		case "unknownBootEnv":
			if benvCheck(name, val) != nil && savePref(name, val) {
				err.AddError(p.RenderUnknown(rt))
			}
		case "unknownTokenTimeout",
			"knownTokenTimeout":
			if intCheck(name, val) {
				savePref(name, val)
			}
		case "debugDhcp",
			"debugRenderer",
			"debugBootEnv",
			"debugFrontend",
			"debugPlugins",
			"logLevel":
			logName, logTarget, logLevel, lErr := p.logCheck(name, val)
			if lErr != nil {
				err.AddError(lErr)
			} else {
				savePref(name, logTarget)
				p.LogFor(logName).SetLevel(logLevel)
			}
		default:
			err.Errorf("Unknown preference %s", name)
		}
	}
	return err.HasError()
}

func (p *DataTracker) setDT(s models.Model) {
	if tgt, ok := s.(dtSetter); ok {
		tgt.setDT(p)
	}
}

func (p *DataTracker) RenderUnknown(rt *RequestTracker) error {
	pref, e := p.Pref("unknownBootEnv")
	if e != nil {
		return e
	}
	envIsh := rt.d("bootenvs").Find(pref)
	if envIsh == nil {
		return fmt.Errorf("No such BootEnv: %s", pref)
	}
	env := AsBootEnv(envIsh)
	err := &models.Error{Object: env, Model: env.Prefix(), Key: env.Key(), Type: "StartupError"}
	if !env.Validated {
		err.AddError(env)
		return err
	}
	if !env.OnlyUnknown {
		err.Errorf("BootEnv %s cannot be used for the unknownBootEnv", env.Name)
		return err
	}
	env.render(rt, nil, err).register(rt)
	return err.HasError()
}

func (p *DataTracker) getBackend(t models.Model) store.Store {
	res, ok := p.objs[t.Prefix()]
	if !ok {
		p.Logger.Fatalf("%s: No registered storage backend!", t.Prefix())
	}
	return res.backingStore
}

func (p *DataTracker) GetToken(tokenString string) (*DrpCustomClaims, error) {
	return p.tokenManager.get(tokenString)
}

func (p *DataTracker) SealClaims(claims *DrpCustomClaims) (string, error) {
	return claims.Seal(p.tokenManager)
}

func (p *DataTracker) Backup() ([]byte, error) {
	keys := make([]string, len(p.objs))
	for k := range p.objs {
		keys = append(keys, k+":ro")
	}
	rt := p.Request(p.Logger, keys...)
	res := map[string][]models.Model{}
	rt.Do(func(_ Stores) {
		for k := range p.objs {
			res[k] = p.objs[k].Items()
		}
	})
	return json.Marshal(res)
}

// Assumes that all locks are held
func (p *DataTracker) ReplaceBackend(rt *RequestTracker, st *DataStack) (hard, soft error) {
	p.Debugf("Replacing backend data store")
	p.Backend = st
	return p.rebuildCache(rt)
}

func (p *DataTracker) MacToMachineUUID(mac string) string {
	p.macAddrMux.RLock()
	defer p.macAddrMux.RUnlock()
	res, ok := p.macAddrMap[mac]
	if ok {
		return res
	}
	return ""
}
