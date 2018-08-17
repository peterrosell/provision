package backend

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/digitalrebar/logger"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/store"
)

func BasicContent() store.Store {
	var (
		localBootParam = &models.Param{
			Name:        `pxelinux-local-boot`,
			Description: `The method pxelinux should use to try to boot to the local disk`,
			Documentation: `
On most systems, using 'localboot 0' is the proper thing to do to have
pxelinux try to boot off the first hard drive.  However, some systems
do not behave properlydoing that, either due to firmware bugs or
malconfigured hard drives.  This param allows you to override 'localboot 0'
with another pxelinux command.  A useful reference for alternate boot methods
is at https://www.syslinux.org/wiki/index.php?title=Comboot/chain.c32`,
			Schema: map[string]string{
				"type":    "string",
				"default": "localboot 0",
			},
		}
		ignoreBoot = &models.BootEnv{
			Name:        `ignore`,
			Description: "The boot environment you should use to have unknown machines boot off their local hard drive",
			OS: models.OsInfo{
				Name: `ignore`,
			},
			OnlyUnknown: true,
			Templates: []models.TemplateInfo{
				{
					Name: "pxelinux",
					Path: `pxelinux.cfg/default`,
					Contents: `DEFAULT local
PROMPT 0
TIMEOUT 10
LABEL local
{{.Param "pxelinux-local-boot"}}
`,
				},
				{
					Name: `ipxe`,
					Path: `default.ipxe`,
					Contents: `#!ipxe
chain {{.ProvisionerURL}}/${netX/mac}.ipxe && exit || goto chainip
:chainip
chain tftp://{{.ProvisionerAddress}}/${netX/ip}.ipxe || exit
`,
				},
			},
			Meta: map[string]string{
				"feature-flags": "change-stage-v2",
				"icon":          "circle thin",
				"color":         "green",
				"title":         "Digital Rebar Provision",
			},
		}

		localBoot = &models.BootEnv{
			Name:        "local",
			Description: "The boot environment you should use to have known machines boot off their local hard drive",
			OS: models.OsInfo{
				Name: "local",
			},
			OnlyUnknown: false,
			Templates: []models.TemplateInfo{
				{
					Name: "pxelinux",
					Path: "pxelinux.cfg/{{.Machine.HexAddress}}",
					Contents: `DEFAULT local
PROMPT 0
TIMEOUT 10
LABEL local
{{.Param "pxelinux-local-boot"}}
`,
				},
				{
					Name: "ipxe",
					Path: "{{.Machine.Address}}.ipxe",
					Contents: `#!ipxe
exit
`,
				},
				{
					Name: "pxelinux-mac",
					Path: "pxelinux.cfg/{{.Machine.MacAddr \"pxelinux\"}}",
					Contents: `DEFAULT local
PROMPT 0
TIMEOUT 10
LABEL local
{{.Param "pxelinux-local-boot"}}
`,
				},
				{
					Name: "ipxe-mac",
					Path: "{{.Machine.MacAddr \"ipxe\"}}.ipxe",
					Contents: `#!ipxe
exit
`,
				},
			},
			Meta: map[string]string{
				"feature-flags": "change-stage-v2",
				"icon":          "radio",
				"color":         "green",
				"title":         "Digital Rebar Provision",
			},
		}
		noneStage = &models.Stage{
			Name:        "none",
			Description: "Noop / Nothing stage",
			Meta: map[string]string{
				"icon":  "circle thin",
				"color": "green",
				"title": "Digital Rebar Provision",
			},
		}
		localStage = &models.Stage{
			Name:        "local",
			BootEnv:     "local",
			Description: "Stage to boot into the local BootEnv.",
			Meta: map[string]string{
				"icon":  "radio",
				"color": "green",
				"title": "Digital Rebar Provision",
			},
		}
		superUser = models.MakeRole("superuser", "*", "*", "*")
	)
	res, _ := store.Open("memory:///")
	bootEnvs, _ := res.MakeSub("bootenvs")
	stages, _ := res.MakeSub("stages")
	roles, _ := res.MakeSub("roles")
	params, _ := res.MakeSub("params")
	localBoot.ClearValidation()
	ignoreBoot.ClearValidation()
	noneStage.ClearValidation()
	localStage.ClearValidation()
	superUser.ClearValidation()
	localBoot.Fill()
	ignoreBoot.Fill()
	noneStage.Fill()
	localStage.Fill()
	superUser.Fill()
	localBootParam.Fill()
	params.Save("pxelinux-local-boot", localBootParam)
	bootEnvs.Save("local", localBoot)
	bootEnvs.Save("ignore", ignoreBoot)
	stages.Save("none", noneStage)
	stages.Save("local", localStage)
	roles.Save("superuser", superUser)
	res.(*store.Memory).SetMetaData(map[string]string{
		"Name":        "BasicStore",
		"Description": "Default objects that must be present",
		"Version":     "Unversioned",
		"Type":        "default",
	})
	return res
}

type DataStack struct {
	store.StackedStore

	writeContent   store.Store
	localContent   store.Store
	saasContents   map[string]store.Store
	defaultContent store.Store
	pluginContents map[string]store.Store
	basicContent   store.Store

	fileRoot   string
	LayerIndex []string
}

func CleanUpStore(st store.Store) error {
	st.Close()
	switch st.Type() {
	case "bolt":
		fst, _ := st.(*store.Bolt)
		return os.Remove(fst.Path)
	case "file":
		fst, _ := st.(*store.File)
		return os.Remove(fst.Path)
	case "directory":
		fst, _ := st.(*store.Directory)
		return os.RemoveAll(fst.Path)
	default:
		return nil
	}
}

func (d *DataStack) Clone() *DataStack {
	dtStore := &DataStack{
		StackedStore:   store.StackedStore{},
		writeContent:   d.writeContent,
		localContent:   d.localContent,
		basicContent:   d.basicContent,
		defaultContent: d.defaultContent,
		saasContents:   map[string]store.Store{},
		pluginContents: map[string]store.Store{},
		fileRoot:       d.fileRoot,
		LayerIndex:     d.LayerIndex,
	}
	dtStore.Open(store.DefaultCodec)
	for k, s := range d.saasContents {
		dtStore.saasContents[k] = s
	}
	for k, s := range d.pluginContents {
		dtStore.pluginContents[k] = s
	}

	return dtStore
}

// FixerUpper takes a the datastack and a store.Store that is to be
// added to the passed stack.  FixerUpper is responsible for making
// sure that it can integrate the new store into the stack, making
// whatever changes are needed to the current datastack to make
// inclusion possible.  It must take care to scan and detect if it
// will not be able to make changes, because any changes it has to
// make to items in the data stack will be live and not possible to
// undo after FixerUpper returns.
type FixerUpper func(*DataStack, store.Store, logger.Logger) error

func (d *DataStack) buildStack(fixup FixerUpper, newStore store.Store, logger logger.Logger) error {
	if ns, ok := newStore.(store.MetaSaver); ok {
		ret := &models.Error{
			Model: "contents",
			Type:  "STORE_ERROR",
			Code:  http.StatusUnprocessableEntity,
		}
		if ns.MetaData()["Name"] == "" {
			ret.Errorf("Content Store must have a name")
		}
		if ns.MetaData()["RequiredFeatures"] != "" {
			stackFeatures := strings.Split(ns.MetaData()["RequiredFeatures"], ",")
			info := &models.Info{}
			info.Fill()
			ofMap := map[string]struct{}{}
			for _, f := range info.Features {
				ofMap[strings.TrimSpace(strings.ToLower(f))] = struct{}{}
			}
			for _, f := range stackFeatures {
				if _, ok := ofMap[strings.TrimSpace(strings.ToLower(f))]; ok {
					continue
				}
				ret.Errorf("dr-provision missing required feature %s", f)
			}
		}
		if ret.ContainsError() {
			return ret
		}
	}
	wrapperFixup := func(ns store.Store, f1, f2 bool) error {
		if fixup != nil && newStore == ns {
			if err := fixup(d, ns, logger); err != nil {
				return err
			}
		}
		if err := d.Push(ns, f1, f2); err != nil {
			return err
		}
		return nil
	}
	d.LayerIndex = []string{"writable"}
	if err := d.Push(d.writeContent, false, true); err != nil {
		return err
	}
	if d.localContent != nil {
		d.LayerIndex = append(d.LayerIndex, "localOverride")
		if err := wrapperFixup(d.localContent, false, false); err != nil {
			return err
		}
	}

	// Sort Names
	saas := make([]string, 0, len(d.saasContents))
	for k := range d.saasContents {
		saas = append(saas, k)
	}
	sort.Strings(saas)

	for _, k := range saas {
		d.LayerIndex = append(d.LayerIndex, "content-"+k)
		if err := wrapperFixup(d.saasContents[k], true, false); err != nil {
			return err
		}
	}

	if d.defaultContent != nil {
		d.LayerIndex = append(d.LayerIndex, "localDefault")
		if err := wrapperFixup(d.defaultContent, false, false); err != nil {
			return err
		}
	}

	plugins := make([]string, 0, len(d.pluginContents))
	for k := range d.pluginContents {
		plugins = append(plugins, k)
	}
	sort.Strings(plugins)

	for _, k := range plugins {
		d.LayerIndex = append(d.LayerIndex, "plugin-"+k)
		if err := wrapperFixup(d.pluginContents[k], true, false); err != nil {
			return err
		}
	}
	d.LayerIndex = append(d.LayerIndex, "basic")
	if err := d.Push(d.basicContent, false, false); err != nil {
		if err = fixBasic(d, d.basicContent, logger); err == nil {
			return d.Push(d.basicContent, false, false)
		}
		return err
	}
	return nil
}

func (d *DataStack) rebuild(oldStore, secrets store.Store,
	logger logger.Logger,
	fixup FixerUpper,
	newStore store.Store) (*DataStack, error, error) {
	if err := d.buildStack(fixup, newStore, logger); err != nil {
		if m, ok := err.(*models.Error); ok {
			return nil, m, nil
		}
		return nil, models.NewError("ValidationError", 422, err.Error()), nil
	}
	hard, soft := ValidateDataTrackerStore(d.fileRoot, d, secrets, logger)
	if hard == nil && oldStore != nil {
		CleanUpStore(oldStore)
	}
	if hard != nil {
	}
	return d, hard, soft
}

func (d *DataStack) RemoveSAAS(name string, logger logger.Logger, secrets store.Store) (*DataStack, error, error) {
	dtStore := d.Clone()
	oldStore, _ := dtStore.saasContents[name]
	delete(dtStore.saasContents, name)
	return dtStore.rebuild(oldStore, secrets, logger, nil, nil)
}

func (d *DataStack) AddReplaceSAAS(
	name string,
	newStore, secrets store.Store,
	logger logger.Logger,
	fixup FixerUpper) (*DataStack, error, error) {
	dtStore := d.Clone()
	oldStore, _ := dtStore.saasContents[name]
	dtStore.saasContents[name] = newStore
	return dtStore.rebuild(oldStore, secrets, logger, fixup, newStore)
}

func (d *DataStack) RemovePluginLayer(name string, logger logger.Logger, secrets store.Store) (*DataStack, error, error) {
	dtStore := d.Clone()
	oldStore, _ := dtStore.pluginContents[name]
	delete(dtStore.pluginContents, name)
	return dtStore.rebuild(oldStore, secrets, logger, nil, nil)
}

func (d *DataStack) AddReplacePluginLayer(
	name string,
	newStore, secrets store.Store,
	logger logger.Logger,
	fixup FixerUpper) (*DataStack, error, error) {
	dtStore := d.Clone()
	oldStore, _ := dtStore.pluginContents[name]
	dtStore.pluginContents[name] = newStore
	return dtStore.rebuild(oldStore, secrets, logger, fixup, newStore)
}

func fixBasic(d *DataStack, l store.Store, logger logger.Logger) error {
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
			if !reflect.DeepEqual(dItem, lItem) {
				return fmt.Errorf("fixBasic: cannot replace %s:%s: item in writable store not equal to static version\n%v\n%v",
					k, key, dItem, lItem)
			}
			logger.Infof("fixBasic: Replacing writable %s:%s with immutable one", k, key)
			toRemove = append(toRemove, []string{k, key})
		}
	}
	for _, item := range toRemove {
		dSub := d.Subs()[item[0]]
		dSub.Remove(item[1])
	}
	return nil
}

func DefaultDataStack(
	dataRoot, backendType, localContent, defaultContent, saasDir, fileRoot string,
	logger logger.Logger) (*DataStack, error) {
	dtStore := &DataStack{
		StackedStore:   store.StackedStore{},
		saasContents:   map[string]store.Store{},
		pluginContents: map[string]store.Store{},
		fileRoot:       fileRoot,
	}

	dtStore.Open(store.DefaultCodec)
	dtStore.basicContent = BasicContent()

	var backendStore store.Store
	if u, err := url.Parse(backendType); err == nil && u.Scheme != "" {
		backendStore, err = store.Open(backendType)
		if err != nil {
			return nil, fmt.Errorf("Failed to open backend content %v: %v", backendType, err)
		}
	} else {
		storeURI := fmt.Sprintf("%s://%s", backendType, dataRoot)
		backendStore, err = store.Open(storeURI)
		if err != nil {
			return nil, fmt.Errorf("Failed to open backend content (%s): %v", storeURI, err)
		}
	}
	if md, ok := backendStore.(store.MetaSaver); ok {
		data := map[string]string{"Name": "BackingStore", "Description": "Writable backing store", "Version": "user"}
		md.SetMetaData(data)
	}
	dtStore.writeContent = backendStore

	if localContent != "" {
		etcStore, err := store.Open(localContent)
		if err != nil {
			return nil, fmt.Errorf("Failed to open local content: %v", err)
		}
		dtStore.localContent = etcStore
		if md, ok := etcStore.(store.MetaSaver); ok {
			d := md.MetaData()
			if _, ok := d["Name"]; !ok {
				data := map[string]string{"Name": "LocalStore", "Description": "Local Override Store", "Version": "user"}
				md.SetMetaData(data)
			}
		}
	}

	// Add SAAS content stores to the DataTracker store here
	dtStore.saasContents = make(map[string]store.Store)
	if saasDir != "" {
		err := filepath.Walk(saasDir, func(filepath string, info os.FileInfo, err error) error {
			if !info.IsDir() {
				ext := path.Ext(filepath)
				codec := "unknown"
				if ext == ".yaml" || ext == ".yml" {
					codec = "yaml"
				} else if ext == ".json" {
					codec = "json"
				}

				if codec == "unknown" {
					// Skip unknown codecs
					return nil
				}

				fs, err := store.Open(fmt.Sprintf("file://%s?codec=%s", filepath, codec))
				if err != nil {
					return fmt.Errorf("Failed to open saas content: %s: %v", filepath, err)
				}

				mst, _ := fs.(store.MetaSaver)
				md := mst.MetaData()
				name := md["Name"]

				dtStore.saasContents[name] = fs
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	if defaultContent != "" {
		defaultStore, err := store.Open(defaultContent)
		if err != nil {
			return nil, fmt.Errorf("Failed to open default content: %v", err)
		}
		dtStore.defaultContent = defaultStore
		if md, ok := defaultStore.(store.MetaSaver); ok {
			d := md.MetaData()
			if _, ok := d["Name"]; !ok {
				data := map[string]string{"Name": "DefaultStore", "Description": "Initial Default Content", "Version": "user", "Type": "default"}
				md.SetMetaData(data)
			} else {
				d["Type"] = "default"
				md.SetMetaData(d)
			}
		}
	}
	return dtStore, dtStore.buildStack(nil, nil, logger)
}
