package backend

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/VictorLowther/jsonpatch2"
	"github.com/digitalrebar/logger"
	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/store"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// RequestTracker tracks a single request
// to the DataTracker.  It represents the
// closest thing to a transaction that we have.
type RequestTracker struct {
	*sync.Mutex
	logger.Logger
	dt    *DataTracker
	locks []string
	d     Stores
	// toRunAfter is to run at the end, but before the locks are dropped.
	// This is used validation.
	// The d Stores are assumed to be locked.
	toRunAfter []func()
	// toPublish is to run at the end, but after the locks are dropped.
	// This is used by the publish system to prevent dead locks.
	// The d Stores are assumed to be NOT locked and not Present.
	toPublishAfter []func()
	Claims         models.ClaimsList
}

func (rt *RequestTracker) HasClaim(scope, action, specific string) bool {
	if len(rt.Claims) == 0 {
		return false
	}
	return rt.Claims.Match(models.MakeRole("", scope, action, specific).Compile())
}

func (rt *RequestTracker) unlocker(u func()) {
	for _, f := range rt.toRunAfter {
		f()
	}
	rt.Lock()
	u()
	rt.d = nil
	for _, f := range rt.toPublishAfter {
		f()
	}
	rt.toPublishAfter = []func(){}
	rt.toRunAfter = []func(){}
	rt.Unlock()
}

func (rt *RequestTracker) runAfter(thunk func()) {
	if rt.d == nil {
		rt.Panicf("Cannot runAfter a function outside Do()")
	}
	if rt.toRunAfter == nil {
		rt.toRunAfter = []func(){}
	}
	rt.toRunAfter = append(rt.toRunAfter, thunk)
}

func (rt *RequestTracker) RunAfter(thunk func()) {
	rt.Lock()
	defer rt.Unlock()
	rt.runAfter(thunk)
}

func (rt *RequestTracker) publishAfter(thunk func()) {
	if rt.toPublishAfter == nil {
		rt.toPublishAfter = []func(){}
	}
	rt.toPublishAfter = append(rt.toPublishAfter, thunk)
}

func (rt *RequestTracker) PublishAfter(thunk func()) {
	rt.Lock()
	defer rt.Unlock()
	rt.publishAfter(thunk)
}

// Request initializes a RequestTracker from the specified DataTracker.
func (p *DataTracker) Request(l logger.Logger, locks ...string) *RequestTracker {
	return &RequestTracker{Mutex: &sync.Mutex{}, dt: p, Logger: l, locks: locks, toRunAfter: []func(){}, toPublishAfter: []func(){}}
}

// PublishEvent records the Event to publish to all publish listeners
// at after the RequestTracker locks have been released.  This
// allows for Events to be published within a locked transaction
// without deadlocking the system.  If the call is made without
// locks, the publishers are notified in this call path.
func (rt *RequestTracker) PublishEvent(e *models.Event) error {
	rt.Lock()
	defer rt.Unlock()
	if rt.dt.publishers == nil {
		return nil
	}
	e.Principal = rt.Principal()
	if rt.d == nil {
		return rt.dt.publishers.publishEvent(e)
	}
	rt.publishAfter(func() { rt.dt.publishers.publishEvent(e) })
	return nil
}

// Publish takes the components of an Event and notifies the publishers
// immediately if not locks are in place.  Otherwise, the action is delayed
// until the locks are released.
func (rt *RequestTracker) Publish(prefix, action, key string, ref interface{}) error {
	return rt.PublishExt(prefix, action, key, ref, nil)
}

// PublishExt takes the components of an Event and notifies the publishers
// immediately if not locks are in place.  Otherwise, the action is delayed
// until the locks are released.
//
// Target specifies the original object or nil
func (rt *RequestTracker) PublishExt(prefix, action, key string, ref, target interface{}) error {
	rt.Lock()
	defer rt.Unlock()
	if rt.dt.publishers == nil {
		return nil
	}
	if rt.d == nil {
		return rt.dt.publishers.PublishExt(prefix, action, key, rt.Principal(), ref, target)

	}
	var toSend interface{}
	switch m := ref.(type) {
	case models.Model:
		toSend = models.Clone(m)
	default:
		toSend = ref
	}
	var toTarget interface{}
	switch m := target.(type) {
	case models.Model:
		toTarget = models.Clone(m)
	default:
		toTarget = target
	}

	rt.publishAfter(func() { rt.dt.publishers.PublishExt(prefix, action, key, rt.Principal(), toSend, toTarget) })
	return nil
}

// find is a helper function to lookup objects in the data tracker.
// It handles the index splitting for the front end.  If the key has
// a colon in the string, the system assumes the first part is the
// index to search under and the rest is the actual key in that index.
// The Index should be unique.
func (rt *RequestTracker) find(prefix, key string) models.Model {
	s := rt.d(prefix)
	if s == nil {
		rt.Panicf("Missing requested lock for %s", prefix)
	}
	parts := strings.SplitN(key, ":", 2)
	if len(parts) == 2 {
		o, err := models.New(prefix)
		if err == nil {
			ref := ModelToBackend(o)
			if idxer, ok := ref.(index.Indexer); ok {
				if idx, ok := idxer.Indexes()[parts[0]]; ok && idx.Unique {
					items, err := index.All(index.Sort(idx))(&s.Index)
					if err == nil {
						return items.Find(parts[1])
					}
				}
			}
		}
	}
	return s.Find(key)
}

// RawFind uses the find helper routine and returns the in-memory
// data store cached object.
func (rt *RequestTracker) RawFind(prefix, key string) models.Model {
	return rt.find(prefix, key)
}

// Find uses the find helper routine and returns a clone of the
// in-memory data store cached object.
func (rt *RequestTracker) Find(prefix, key string) models.Model {
	res := rt.find(prefix, key)
	if res != nil {
		return ModelToBackend(models.Clone(res))
	}
	return nil
}

// FindByIndex uses the provided index and key (for that index) to return
// the object.  The object returned is a clone.
func (rt *RequestTracker) FindByIndex(prefix string, idx index.Maker, key string) models.Model {
	items, err := index.Sort(idx)(rt.Index(prefix))
	if err != nil {
		rt.Errorf("Error sorting %s: %v", prefix, err)
		return nil
	}
	return items.Find(key)
}

// Index returns the index specified by that name.
// No validation is done on the name.
func (rt *RequestTracker) Index(name string) *index.Index {
	return &rt.d(name).Index
}

// Do takes a function that takes the lock stores specified
// when the RequestTracker was created and executes it
// with the locks taken and then unlocks the locks when complete.
// It is assumed that is as lamdba function.
func (rt *RequestTracker) Do(thunk func(Stores)) {
	rt.Lock()
	if rt.d != nil {
		rt.Unlock()
		rt.Panicf("Recursive lock of request tracker!")
	}
	d, unlocker := rt.dt.lockEnts(rt.locks...)
	rt.d = d
	rt.Unlock()
	defer rt.unlocker(unlocker)
	thunk(d)
}

// AllLocked takes a function that takes the lock stores.
// In this case, all stores are locked and sent the function.
// Upon completion, the locks are released.
// It is assumed that is as lamdba function.
func (rt *RequestTracker) AllLocked(thunk func(Stores)) {
	rt.Lock()
	d, unlocker := rt.dt.lockAll()
	rt.d = d
	rt.Unlock()
	defer rt.unlocker(unlocker)
	thunk(d)
}

func (rt *RequestTracker) backend(m models.Model) store.Store {
	return rt.dt.getBackend(m)
}

func (rt *RequestTracker) stores(s string) *Store {
	return rt.d(s)
}

// spkibrt is a helper function that takes a model and
// explodes it into a bunch of components.
//   s = stores for this RequestTracker instance
//   p = the prefix of the request object.
//   k = the key of the requested object.
//   i = the current idx for finding those objects.
//   b = the backing store for that index.
//   r = refenence to the input object.
//   t = target - cloned version of the looked up object.
//
// Some of these values are empty/blank if the object is not found.
//
// A common use is to use this function to take a partially specified
// object to return a clone of the populated object.
func (rt *RequestTracker) spkibrt(obj models.Model) (
	s Stores,
	prefix, key string,
	idx *Store, bk store.Store,
	ref, target store.KeySaver) {
	if rt.d == nil {
		rt.Panicf("RequestTracker used outside of Do")
		return
	}
	s = rt.d
	prefix = obj.Prefix()
	idx = rt.d(prefix)
	bk = idx.backingStore
	if obj == nil {
		return
	}
	key = obj.Key()
	m := idx.Find(key)
	ref = ModelToBackend(obj)
	if m != nil {
		target = m.(store.KeySaver)
	}
	return
}

// Create takes an object and attempts to save it.  saved is
// true if the object is actually saved.  error indicates the
// actual error including validation errors. A "create" event
// is generated from this call.
//
// Assumes locks are held if appropriate.
func (rt *RequestTracker) Create(obj models.Model) (saved bool, err error) {
	if ms, ok := obj.(models.Filler); ok {
		ms.Fill()
	}
	_, prefix, key, idx, backend, ref, target := rt.spkibrt(obj)
	if key == "" {
		return false, &models.Error{
			Type:     "CREATE",
			Model:    prefix,
			Messages: []string{"Empty key not allowed"},
			Code:     http.StatusBadRequest,
		}
	}
	if target != nil {
		return false, &models.Error{
			Type:     "CREATE",
			Model:    prefix,
			Key:      key,
			Messages: []string{"already exists"},
			Code:     http.StatusConflict,
		}
	}
	ref.(validator).setRT(rt)
	checker, checkOK := ref.(models.Validator)
	if checkOK {
		checker.ClearValidation()
	}

	saved, err = store.Create(backend, ref)
	if saved {
		ref.(validator).clearRT()
		idx.Add(ref)

		rt.Publish(prefix, "create", key, ref)
	}

	return saved, err
}

// Remove takes a complete or partial object and removes
// the object from the system.  removed is true if the object
// is removed.  error indicates the error that caused the remove
// to fail.  A "delete" event is generated from this routine.
//
// Assumes locks are held if appropriate.
func (rt *RequestTracker) Remove(obj models.Model) (removed bool, err error) {
	_, prefix, key, idx, backend, _, item := rt.spkibrt(obj)
	if item == nil {
		return false, &models.Error{
			Type:     "DELETE",
			Code:     http.StatusNotFound,
			Key:      key,
			Model:    prefix,
			Messages: []string{"Not Found"},
		}
	}
	item.(validator).setRT(rt)
	removed, err = store.Remove(backend, item.(store.KeySaver))
	if removed {
		idx.Remove(item)
		rt.Publish(prefix, "delete", key, item)
	}
	return removed, err
}

// Patch takes a partially specified object to define the key space,
// a key to find the object, and a JSON patch object to apply to
// the found object.  Upon success, the new object is returned. Failure
// returned in the error field.  This will generate an "update" event.
//
// Assumes locks are held as appropriate.
func (rt *RequestTracker) Patch(obj models.Model, key string, patch jsonpatch2.Patch) (models.Model, error) {
	_, prefix, _, idx, backend, _, _ := rt.spkibrt(obj)
	ref := idx.Find(key)
	if ref == nil {
		return nil, &models.Error{
			Type:     "PATCH",
			Code:     http.StatusNotFound,
			Key:      key,
			Model:    prefix,
			Messages: []string{"Not Found"},
		}
	}
	target := ref.(store.KeySaver)
	buf, fatalErr := json.Marshal(target)
	if fatalErr != nil {
		rt.Fatalf("Non-JSON encodable %v:%v stored in cache: %v", obj.Prefix(), key, fatalErr)
	}
	resBuf, patchErr, loc := patch.Apply(buf)
	rt.Tracef("Patching %s", string(buf))
	rt.Tracef("Patched to: %s", string(resBuf))
	if patchErr != nil {
		err := &models.Error{
			Code:  http.StatusConflict,
			Key:   key,
			Model: prefix,
			Type:  "PATCH",
		}
		rt.Tracef("Patched to: %s", string(resBuf))
		err.Errorf("Patch error at line %d: %v", loc, patchErr)
		buf, _ := json.Marshal(patch[loc])
		err.Errorf("Patch line: %v", string(buf))
		return nil, err
	}
	toSave := target.New()
	if err := json.Unmarshal(resBuf, &toSave); err != nil {
		retErr := &models.Error{
			Code:  http.StatusNotAcceptable,
			Key:   key,
			Model: prefix,
			Type:  "PATCH",
		}
		retErr.AddError(err)
		return nil, retErr
	}
	if ms, ok := toSave.(models.Filler); ok {
		ms.Fill()
	}
	toSave.(validator).setRT(rt)
	checker, checkOK := toSave.(models.Validator)
	if checkOK {
		checker.ClearValidation()
	}
	if obj != nil {
		a, aok := obj.(models.ChangeForcer)
		if aok {
			rt.Tracef("obj: %#v", obj)
			rt.Tracef("a: %#v", a)
			if a != nil && a.ChangeForced() {
				rt.Tracef("Forcing change for %s:%s", prefix, key)
				toSave.(models.ChangeForcer).ForceChange()
			}
		}
	}
	saved, err := store.Update(backend, toSave)
	toSave.(validator).clearRT()
	if saved {
		idx.Add(toSave)
		rt.PublishExt(prefix, "update", key, toSave, ref)
	}
	return toSave, err
}

// Update takes a fully specified object and replaces an existing
// object in the data store assuming the new object is valid.  saved
// is true if the object is saved.  error indicates failure.  An
// "update" event is generated from this call.
//
// Assumes locks are held as appropriate.
func (rt *RequestTracker) Update(obj models.Model) (saved bool, err error) {
	_, prefix, key, idx, backend, ref, target := rt.spkibrt(obj)
	if target == nil {
		return false, &models.Error{
			Type:     "PUT",
			Code:     http.StatusNotFound,
			Key:      key,
			Model:    prefix,
			Messages: []string{"Not Found"},
		}
	}
	if ms, ok := ref.(models.Filler); ok {
		ms.Fill()
	}
	ref.(validator).setRT(rt)
	checker, checkOK := ref.(models.Validator)
	if checkOK {
		checker.ClearValidation()
	}
	saved, err = store.Update(backend, ref)
	ref.(validator).clearRT()
	if saved {
		idx.Add(ref)
		rt.PublishExt(prefix, "update", key, ref, target)
	}
	return saved, err
}

// Save takes a fully specified object and saves it to the data store
// and backing index. This will generate a "save" event.
// The difference between Update and Save is that Update will go
// through the OnChange callback system.  Save will NOT.  Both calls
// will call BeforeSave and AfterSave.
//
// Assumes that locks are held as appropriate.
func (rt *RequestTracker) Save(obj models.Model) (saved bool, err error) {
	_, prefix, key, idx, backend, ref, target := rt.spkibrt(obj)
	if ms, ok := ref.(models.Filler); ok {
		ms.Fill()
	}
	ref.(validator).setRT(rt)
	checker, checkOK := ref.(models.Validator)
	if checkOK {
		checker.ClearValidation()
	}

	saved, err = store.Save(backend, ref)
	ref.(validator).clearRT()
	if saved {
		idx.Add(ref)
		rt.PublishExt(prefix, "save", key, ref, target)
	}
	return saved, err
}

func (rt *RequestTracker) decryptParam(
	obj models.Model,
	name string, val interface{},
	decrypt bool) interface{} {
	if !decrypt {
		return val
	}
	pobj := rt.find("params", name)
	if pobj == nil {
		return val
	}
	param := AsParam(pobj)
	if !param.Secure {
		return val
	}
	sd := &models.SecureData{}
	models.Remarshal(val, sd)
	var ret interface{}
	pk, err := rt.PrivateKeyFor(obj)
	if err != nil {
		panic(err.Error())
	}
	if err := sd.Unmarshal(pk, &ret); err != nil {
		return val
	}
	return ret
}

func (rt *RequestTracker) getAggParams(obj models.Paramer,
	params map[string]interface{}, aggregate bool) (sources map[string]models.Paramer) {
	sources = map[string]models.Paramer{}
	for k := range params {
		sources[k] = obj
	}
	if !aggregate {
		return
	}
	subObjs := []models.Paramer{}
	var profiles []string
	var stage string
	switch ref := obj.(type) {
	case *rMachine:
		profiles, stage = ref.Profiles, ref.Stage
	case *models.Machine:
		profiles, stage = ref.Profiles, ref.Stage
	case *Machine:
		profiles, stage = ref.Profiles, ref.Stage
	}
	for _, pn := range profiles {
		if pobj := rt.Find("profiles", pn); pobj != nil {
			subObjs = append(subObjs, pobj.(models.Paramer))
		}
	}
	if stage != "" {
		if sobj := rt.Find("stages", stage); sobj != nil {
			for _, pn := range AsStage(sobj).Profiles {
				if pobj := rt.Find("profiles", pn); pobj != nil {
					subObjs = append(subObjs, pobj.(models.Paramer))
				}
			}
		}
	}
	if pobj := rt.Find("profiles", rt.dt.GlobalProfileName); pobj != nil {
		subObjs = append(subObjs, pobj.(models.Paramer))
	}
	for _, sub := range subObjs {
		for k, v := range sub.GetParams() {
			if _, ok := params[k]; !ok {
				params[k] = v
				sources[k] = sub
			}
		}
	}
	return
}

func (rt *RequestTracker) GetParams(obj models.Paramer, aggregate bool, decrypt bool) map[string]interface{} {
	res := obj.GetParams()
	sources := rt.getAggParams(obj, res, aggregate)
	if decrypt {
		for k, src := range sources {
			res[k] = rt.decryptParam(src, k, res[k], decrypt)
		}
	}
	return res
}

func (rt *RequestTracker) GetParam(obj models.Paramer, key string, aggregate bool, decrypt bool) (interface{}, bool) {
	res := obj.GetParams()
	sources := rt.getAggParams(obj, res, aggregate)
	if v, ok := res[key]; ok {
		return rt.decryptParam(sources[key], key, v, decrypt), true
	}
	if aggregate {
		if pobj := rt.Find("params", key); pobj != nil {
			rt.Tracef("Param %s not defined, falling back to default value", key)
			return AsParam(pobj).DefaultValue()
		}
	}
	return nil, false
}

func (rt *RequestTracker) urlFor(scheme string, remoteIP net.IP, port int) string {
	return fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(rt.dt.LocalIP(remoteIP), strconv.Itoa(port)))
}

// ApiURL is a helper function to return the appropriate
// URL to access the API based upon the remote IP.
func (rt *RequestTracker) ApiURL(remoteIP net.IP) string {
	return rt.urlFor("https", remoteIP, rt.dt.ApiPort)
}

// FileURL is a helper function to return the appropriate
// URL to access the FileServer based upon the remote IP.
func (rt *RequestTracker) FileURL(remoteIP net.IP) string {
	return rt.urlFor("http", remoteIP, rt.dt.StaticPort)
}

// SealClaims takes a set of auth claims and signs them to
// make an Token for authentication purposes.
func (rt *RequestTracker) SealClaims(claims *DrpCustomClaims) (string, error) {
	return rt.dt.SealClaims(claims)
}

// MachineForMac looks up a Machine by the specified MAC address.
func (rt *RequestTracker) MachineForMac(mac string) *Machine {
	m := rt.Find("machines", rt.dt.MacToMachineUUID(mac))
	if m != nil {
		return AsMachine(m)
	}
	return nil
}

// Prefs returns the current Prefs in the data tracker.
func (rt *RequestTracker) Prefs() map[string]string {
	return rt.dt.Prefs()
}

func (rt *RequestTracker) rotateKeyFor(m models.Model) ([]byte, error) {
	_, pk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	key := pk[:]
	return key, rt.dt.Secrets.Save(m.Prefix()+"-"+m.Key(), key)
}

func (rt *RequestTracker) DeleteKeyFor(m models.Model) error {
	rt.dt.secretsMux.Lock()
	defer rt.dt.secretsMux.Unlock()
	return rt.dt.Secrets.Remove(m.Prefix() + "-" + m.Key())
}

func (rt *RequestTracker) PrivateKeyFor(m models.Model) ([]byte, error) {
	rt.dt.secretsMux.Lock()
	defer rt.dt.secretsMux.Unlock()
	var res []byte
	if err := rt.dt.Secrets.Load(m.Prefix()+"-"+m.Key(), &res); err != nil {
		if os.IsNotExist(err) {
			return rt.rotateKeyFor(m)
		}
		return nil, err
	}
	return res, nil
}

func (rt *RequestTracker) PublicKeyFor(m models.Model) ([]byte, error) {
	privateKey, err := rt.PrivateKeyFor(m)
	if err != nil || privateKey == nil || len(privateKey) != 32 {
		return nil, err
	}
	res, pk := [32]byte{}, [32]byte{}
	copy(pk[:], privateKey)
	curve25519.ScalarBaseMult(&res, &pk)
	return res[:], nil
}
