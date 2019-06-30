package backend

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"text/template"

	"github.com/VictorLowther/jsonpatch2/utils"
	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/provision/store"
	"github.com/mholt/archiver"
)

var explodeMux = &sync.Mutex{}

// BootEnv encapsulates the machine-agnostic information needed by the
// provisioner to set up a boot environment.
type BootEnv struct {
	*models.BootEnv
	validate
	renderers      renderers
	pathLookasides map[string]func(string) (io.Reader, error)
	realArches     map[string]models.ArchInfo
	installRepos   map[string]*Repo
	kernelVerified bool
	rootTemplate   *template.Template
	tmplMux        sync.Mutex
}

func (b *BootEnv) NetBoot() bool {
	return b.OnlyUnknown || len(b.realArches) > 0
}

func (b *BootEnv) SetReadOnly(nb bool) {
	b.ReadOnly = nb
}

func (b *BootEnv) SaveClean() store.KeySaver {
	mod := *b.BootEnv
	mod.ClearValidation()
	return ModelToBackend(&mod)
}

func (b *BootEnv) Indexes() map[string]index.Maker {
	fix := AsBootEnv
	res := index.MakeBaseIndexes(b)
	res["Name"] = index.Maker{
		Unique: true,
		Type:   "string",
		Less:   func(i, j models.Model) bool { return fix(i).Name < fix(j).Name },
		Eq:     func(i, j models.Model) bool { return fix(i).Name == fix(j).Name },
		Match:  func(i models.Model, re *regexp.Regexp) bool { return re.MatchString(fix(i).Name) },
		Tests: func(ref models.Model) (gte, gt index.Test) {
			name := fix(ref).Name
			return func(s models.Model) bool {
					return fix(s).Name >= name
				},
				func(s models.Model) bool {
					return fix(s).Name > name
				}
		},
		Fill: func(s string) (models.Model, error) {
			res := fix(b.New())
			res.Name = s
			return res, nil
		},
	}
	res["OsName"] = index.Maker{
		Unique: false,
		Type:   "string",
		Less:   func(i, j models.Model) bool { return fix(i).OS.Name < fix(j).OS.Name },
		Eq:     func(i, j models.Model) bool { return fix(i).Name == fix(j).OS.Name },
		Match:  func(i models.Model, re *regexp.Regexp) bool { return re.MatchString(fix(i).OS.Name) },
		Tests: func(ref models.Model) (gte, gt index.Test) {
			name := fix(ref).OS.Name
			return func(s models.Model) bool {
					return fix(s).OS.Name >= name
				},
				func(s models.Model) bool {
					return fix(s).OS.Name > name
				}
		},
		Fill: func(s string) (models.Model, error) {
			res := fix(b.New())
			res.OS.Name = s
			return res, nil
		},
	}
	res["OnlyUnknown"] = index.MakeUnordered(
		"boolean",
		func(i, j models.Model) bool {
			return fix(i).OnlyUnknown == fix(j).OnlyUnknown
		},
		func(s string) (models.Model, error) {
			res := fix(b.New())
			switch s {
			case "true":
				res.OnlyUnknown = true
			case "false":
				res.OnlyUnknown = false
			default:
				return nil, errors.New("OnlyUnknown must be true or false")
			}
			return res, nil
		})
	return res
}

func (b *BootEnv) regenArches() {
	arches := map[string]models.ArchInfo{}
	if b.Kernel != "" {
		arches["amd64"] = models.ArchInfo{
			Kernel:     b.Kernel,
			Initrds:    b.Initrds,
			BootParams: b.BootParams,
			IsoFile:    b.OS.IsoFile,
			Sha256:     b.OS.IsoSha256,
			IsoUrl:     b.OS.IsoUrl,
		}
	}
	if len(b.OS.SupportedArchitectures) > 0 {
		for k, v := range b.OS.SupportedArchitectures {
			k2, _ := models.SupportedArch(k)
			arches[k2] = v
		}
	}
	for k := range arches {
		if arches[k].Kernel == "" {
			b.Errorf("Arch %s is missing a kernel!", k)
		}
		if arches[k].BootParams != "" {
			_, err := template.New("machine").Funcs(models.DrpSafeFuncMap()).Parse(arches[k].BootParams)
			if err != nil {
				b.Errorf("Error compiling boot parameter template for arch %s: %v", k, err)
			}
		}
	}
	b.realArches = arches
}

func (b *BootEnv) Backend() store.Store {
	return b.rt.backend(b)
}

func (b *BootEnv) RealArch(arch string) models.ArchInfo {
	return b.realArches[b.ArchFor(arch)]
}

func (b *BootEnv) ArchFor(arch string) string {
	for k := range b.realArches {
		if models.ArchEqual(arch, k) {
			return k
		}
	}
	return ""
}

func (b *BootEnv) canLocalBoot(rt *RequestTracker, arch string) error {
	if !b.NetBoot() {
		return nil
	}
	ret := &models.Error{
		Code: http.StatusNotAcceptable,
		Type: "bootenv",
		Key:  b.Name,
	}
	ourArch := b.ArchFor(arch)
	if ourArch == "" {
		ret.Errorf("Cannot handle arch %s", arch)
		return ret
	}
	archInfo := b.realArches[ourArch]
	kPath := b.localPathFor(rt, archInfo.Kernel, ourArch)
	kernelStat, err := os.Stat(kPath)
	if err != nil {
		ret.Errorf("bootenv: %s: missing kernel %s (%s) for arch %s",
			b.Name,
			b.Kernel,
			rt.dt.reportPath(kPath),
			arch)
	} else if !kernelStat.Mode().IsRegular() {
		ret.Errorf("bootenv: %s: invalid kernel %s (%s) for arch %s",
			b.Name,
			b.Kernel,
			rt.dt.reportPath(kPath),
			arch)
	}
	// Ditto for all the initrds.
	if len(b.Initrds) > 0 {
		for _, initrd := range b.Initrds {
			iPath := b.localPathFor(rt, initrd, arch)
			initrdStat, err := os.Stat(iPath)
			if err != nil {
				ret.Errorf("bootenv: %s: missing initrd %s (%s) for arch %s",
					b.Name,
					initrd,
					rt.dt.reportPath(iPath),
					arch)
			} else if !initrdStat.Mode().IsRegular() {
				ret.Errorf("bootenv: %s: invalid initrd %s (%s) for arch %s",
					b.Name,
					initrd,
					rt.dt.reportPath(iPath),
					arch)
			}
		}
	}
	return ret.HasError()
}

func (b *BootEnv) CanArchBoot(rt *RequestTracker, arch string) error {
	if !b.NetBoot() {
		return nil
	}
	ourArch := b.ArchFor(arch)
	if _, ok := b.installRepos[ourArch]; ok {
		return nil
	}
	return b.canLocalBoot(rt, arch)
}

func (b *BootEnv) PathFor(f, arch string) string {
	res := b.OS.Name
	ourArch := b.ArchFor(arch)
	if ourArch == "" {
		panic(fmt.Errorf("Unknown arch %s", arch))
	}
	if testArch, _ := models.SupportedArch(ourArch); testArch != "amd64" {
		res = path.Join(res, ourArch)
	}
	if strings.HasSuffix(b.Name, "-install") {
		res = path.Join(res, "install")
	}
	return path.Clean(path.Join("/", res, f))
}

type rt struct {
	io.ReadCloser
	sz int64
}

func (r *rt) Size() int64 {
	return r.sz
}

func (b *BootEnv) fillInstallRepos() {
	if !b.NetBoot() {
		return
	}
	if b.OS.Name == "" {
		b.rt.Errorf("BootEnv %s: Missing OS.Name, cannot fill install repos", b.Name)
		return
	}
	b.rt.Tracef("fillInstallRepo: Looking for global profile")
	o := b.rt.find("profiles", b.rt.dt.GlobalProfileName)
	if o == nil {
		return
	}
	p := AsProfile(o)
	repos := []*Repo{}
	r, ok := b.rt.GetParam(p, "package-repositories", true, false)
	if !ok || utils.Remarshal(r, &repos) != nil {
		b.rt.Infof("BootEnv %s: No package repositories to use", b.Name)
		return
	}
	for _, r := range repos {
		b.rt.Debugf("BootEnv %s: Considering repo %s", b.Name, r.Tag)
		if !r.InstallSource || len(r.OS) != 1 || r.OS[0] != b.OS.Name {
			continue
		}
		arch := r.Arch
		realArch := b.ArchFor(arch)
		archInfo, ok := b.realArches[realArch]
		if !ok {
			continue
		}
		b.rt.Infof("BootEnv %s: Using repo %s as an install source", b.Name, r.Tag)
		b.kernelVerified = true
		b.installRepos[realArch] = r
		pf := b.PathFor("", arch)
		fileRoot := b.rt.dt.FileRoot
		l := b.rt.Logger
		b.pathLookasides[realArch] = func(p string) (io.Reader, error) {
			// Always use local copy if available
			if _, err := os.Stat(path.Join(fileRoot, b.PathFor("", arch))); err == nil || b.installRepos[realArch] == nil {
				return nil, nil
			}
			tgtUri := strings.TrimSuffix(b.installRepos[realArch].URL, "/") + strings.TrimPrefix(p, pf)
			if b.installRepos[realArch].BootLoc != "" {
				if strings.HasSuffix(p, b.Kernel) {
					tgtUri = strings.TrimSuffix(b.installRepos[realArch].BootLoc, "/") + "/" + path.Base(archInfo.Kernel)
				} else {
					for _, i := range archInfo.Initrds {
						if strings.HasSuffix(p, i) {
							tgtUri = strings.TrimSuffix(b.installRepos[realArch].BootLoc, "/") + "/" + path.Base(i)
							break
						}
					}
				}
			}
			l.Debugf("Proxying %s to %s", p, tgtUri)
			resp, err := http.Get(tgtUri)
			if err != nil {
				return nil, err
			}
			if resp.ContentLength < 0 {
				return resp.Body, nil
			}
			return &rt{resp.Body, resp.ContentLength}, nil
		}
		return
	}
}

func (b *BootEnv) AddDynamicTree() {
	if b.pathLookasides != nil {
		for k, p := range b.pathLookasides {
			b.rt.dt.FS.AddDynamicTree(b.PathFor("", k), p)
		}
	}
}

func (b *BootEnv) localPathFor(rt *RequestTracker, f, arch string) string {
	return path.Join(rt.dt.FileRoot, b.PathFor(f, arch))
}

func (b *BootEnv) genRoot(commonRoot *template.Template, e models.ErrorAdder) *template.Template {
	res := models.MergeTemplates(commonRoot, b.Templates, e)
	for i, tmpl := range b.Templates {
		if tmpl.Path == "" {
			e.Errorf("Template[%d] needs a Path", i)
		}
	}
	if b.HasError() != nil {
		return nil
	}
	return res
}

func explodeISO(rt *RequestTracker, envName, osName, fileRoot, isoFile, dest, shaSum string) {
	p := rt.dt
	explodeMux.Lock()
	defer explodeMux.Unlock()
	// Only check the has if we have one.
	if shaSum != "" {
		f, err := os.Open(isoFile)
		if err != nil {
			rt.Errorf("Explode ISO: failed to open iso file %s: %v", p.reportPath(isoFile), err)
			return
		}
		defer f.Close()
		hasher := sha256.New()
		if _, err := io.Copy(hasher, f); err != nil {
			rt.Errorf("Explode ISO: failed to read iso file %s: %v", p.reportPath(isoFile), err)
			return
		}
		hash := hex.EncodeToString(hasher.Sum(nil))
		if hash != shaSum {
			rt.Errorf("Explode ISO: SHA256 bad. actual: %v expected: %v", hash, shaSum)
			return
		}
	}
	// Call extract script
	// /explode_iso.sh b.OS.Name fileRoot isoPath path.Dir(canaryPath)
	cmdName := path.Join(fileRoot, "explode_iso.sh")
	cmdArgs := []string{osName, fileRoot, isoFile, dest, shaSum}
	out, err := exec.Command(cmdName, cmdArgs...).CombinedOutput()
	if err != nil {
		rt.Errorf("Explode ISO: explode_iso.sh failed for %s: %s", envName, err)
		rt.Errorf("Command output:\n%s", string(out))
	}
}

func (b *BootEnv) sledgeExploder(rt *RequestTracker, arch string, archInfo models.ArchInfo) func(*RequestTracker) {
	lp := b.localPathFor(rt, "", arch)
	isoPath := filepath.Join(rt.dt.FileRoot, "isos", archInfo.IsoFile)

	fp, err := os.Open(isoPath)
	if err != nil {
		rt.Infof("Sledgehammer image %s not a tarball, exiting to usual extract path.", isoPath)
		return nil
	}
	defer fp.Close()
	opener, err := archiver.ByHeader(fp)
	if err != nil {
		rt.Infof("Sledgehammer image %s not a tarball, exiting to usual extract path.", isoPath)
		return nil
	}
	return func(rt *RequestTracker) {
		explodeMux.Lock()
		defer explodeMux.Unlock()
		sPath := filepath.Join(lp, path.Dir(archInfo.Kernel))
		if _, err := os.Stat(b.localPathFor(rt, archInfo.Kernel, arch)); err == nil {
			rt.Infof("BootEnv %s: %s already exists", b.Name, sPath)
			return
		}
		rt.Errorf("Sledgehammer: Extracting %s to %s", archInfo.IsoFile, lp)
		if err := opener.Unarchive(isoPath, lp); err != nil {
			os.RemoveAll(sPath)
			rt.Errorf("Error extracting sledgehammer archive %s: %v", isoPath, err)
		} else {
			rt.Infof("Sledgehammer arch %s archive %s extracted to %s", arch, isoPath, sPath)
		}
	}
}

func (b *BootEnv) realExploder(rt *RequestTracker, arch string, archInfo models.ArchInfo) func(*RequestTracker) {
	// Have we already exploded this?  If file exists, then good!
	canaryPath := b.localPathFor(rt, "."+strings.Replace(b.OS.Name, "/", "_", -1)+".rebar_canary", arch)
	buf, err := ioutil.ReadFile(canaryPath)
	if err == nil && string(bytes.TrimSpace(buf)) == archInfo.Sha256 {
		rt.Infof("Explode ISO: canary file %s, in place and has proper SHA256\n", rt.dt.reportPath(canaryPath))
		return nil
	}
	isoPath := filepath.Join(rt.dt.FileRoot, "isos", archInfo.IsoFile)
	lPath := b.localPathFor(rt, "", arch)
	return func(rt *RequestTracker) {
		name := b.Name
		osName := b.OS.Name
		iPath := isoPath
		localPath := lPath
		sha256 := archInfo.Sha256
		explodeISO(rt, name, osName, rt.dt.FileRoot, iPath, localPath, sha256)
	}
}

func (b *BootEnv) IsoExploders(rt *RequestTracker) []func(*RequestTracker) {
	res := []func(*RequestTracker){}
	if b.OS.Name == "" {
		rt.Errorf("Explode ISO: Skipping because BootEnv %s is missing OS.Name", b.Name)
		return res
	}
	for arch := range b.realArches {
		archInfo := b.realArches[arch]
		// Only work on things that are requested.
		isoFile := archInfo.IsoFile
		if isoFile == "" {
			rt.Infof("Explode ISO: Skipping %s becausing no iso image specified\n", b.Name)
			continue
		}
		if _, err := os.Stat(filepath.Join(rt.dt.FileRoot, "isos", isoFile)); err != nil {
			if b.installRepos[arch] != nil {
				rt.Infof("BootEnv: Explode ISO: ISO does not exist, falling back to install repo at %s", b.installRepos[arch].URL)
			} else {
				rt.Infof("BootEnv %s : Explode ISO: Iso %s does not exist. Will not be able to PXE boot arch %s",
					b.Name, isoFile, arch)
			}
			continue
		}
		var exploder func(*RequestTracker)
		if b.OS.Name == "sledgehammer" {
			exploder = b.sledgeExploder(rt, arch, archInfo)
		}
		if exploder == nil {
			exploder = b.realExploder(rt, arch, archInfo)
		}
		if exploder != nil {
			res = append(res, exploder)
		}
	}
	return res
}

func (b *BootEnv) ExplodeIsos(rt *RequestTracker) {
	newRT := rt.dt.Request(rt.Logger)
	exploders := b.IsoExploders(newRT)
	for i := range exploders {
		go exploders[i](newRT)
	}
}

func (b *BootEnv) IsoFor(name string) bool {
	for _, archInfo := range b.realArches {
		if name == archInfo.IsoFile {
			return true
		}
	}
	return false
}

func (b *BootEnv) Validate() {
	b.renderers = renderers{}
	b.pathLookasides = map[string]func(string) (io.Reader, error){}
	b.installRepos = map[string]*Repo{}
	b.regenArches()
	b.BootEnv.Validate()
	// First, the stuff that must be correct in order for
	b.AddError(index.CheckUnique(b, b.rt.stores("bootenvs").Items()))
	// If our basic templates do not parse, it is game over for us
	b.rt.dt.tmplMux.Lock()
	b.tmplMux.Lock()
	root := b.genRoot(b.rt.dt.rootTemplate, b)
	b.rt.dt.tmplMux.Unlock()
	if root != nil {
		b.rootTemplate = root
	}
	b.tmplMux.Unlock()
	if !b.SetValid() {
		// If we have not been validated at this point, return.
		return
	}
	if b.NetBoot() && b.OS.Name == "" {
		b.Errorf("bootenv: Missing OS.Name")
	}
	// OK, we are sane, if not useable.  Check to see if we are useable
	seenPxeLinux := false
	seenIPXE := false
	for _, template := range b.Templates {
		if template.Name == "pxelinux" || template.Name == "pxelinux-mac" {
			seenPxeLinux = true
		}
		if template.Name == "ipxe" || template.Name == "ipxe-mac" {
			seenIPXE = true
		}
	}
	if !(seenPxeLinux || seenIPXE) && b.Kernel != "" && b.Meta["KernelIsLoader"] != "true" {
		b.Errorf("bootenv: Missing elilo or pxelinux template")
	}
	// Make sure the ISO for this bootenv has been exploded locally so that
	// the boot env can use its contents.
	b.fillInstallRepos()
	if b.OnlyUnknown {
		b.renderers = append(b.renderers, b.render(b.rt, nil, b)...)
	} else {
		machines := b.rt.stores("machines")
		if machines != nil {
			for _, i := range machines.Items() {
				machine := AsMachine(i)
				if machine.BootEnv != b.Name {
					continue
				}
				b.renderers = append(b.renderers, b.render(b.rt, machine, b)...)
			}
		}
	}
	b.SetAvailable()
	b.ExplodeIsos(b.rt)
}

func (b *BootEnv) OnLoad() error {
	defer func() { b.rt = nil }()
	b.Fill()
	return b.BeforeSave()
}

func (b *BootEnv) New() store.KeySaver {
	res := &BootEnv{BootEnv: &models.BootEnv{}}
	if b.BootEnv != nil && b.ChangeForced() {
		res.ForceChange()
	}
	res.rt = b.rt
	return res
}

func (b *BootEnv) BeforeSave() error {
	b.Validate()
	if !b.Validated {
		return b.MakeError(422, ValidationError, b)
	}
	return nil
}

func (b *BootEnv) BeforeDelete() error {
	e := &models.Error{Code: 409, Type: StillInUseError, Model: b.Prefix(), Key: b.Key()}
	machines := b.rt.stores("machines")
	stages := b.rt.stores("stages")
	prefToFind := ""
	if b.OnlyUnknown {
		prefToFind = "unknownBootEnv"
	} else {
		prefToFind = "defaultBootEnv"
	}
	if b.rt.dt.pref(prefToFind) == b.Name {
		e.Errorf("BootEnv %s is the active %s, cannot remove it", b.Name, prefToFind)
	}
	if !b.OnlyUnknown {
		for _, i := range machines.Items() {
			machine := AsMachine(i)
			if machine.BootEnv != b.Name {
				continue
			}
			e.Errorf("Bootenv %s in use by Machine %s", b.Name, machine.Name)
		}
		for _, i := range stages.Items() {
			stage := AsStage(i)
			if stage.BootEnv != b.Name {
				continue
			}
			e.Errorf("Bootenv %s in use by Stage %s", b.Name, stage.Name)
		}
	}
	return e.HasError()
}

func (b *BootEnv) AfterDelete() {
	if b.OnlyUnknown {
		err := &models.Error{Object: b}
		rts := b.render(b.rt, nil, err)
		if err.ContainsError() {
			b.Errors = err.Messages
		} else {
			rts.deregister(b.rt)
		}
		idx, idxerr := index.All(
			index.Sort(b.Indexes()["OsName"]),
			index.Eq(b.OS.Name))(&(b.rt.stores("bootenvs").Index))
		if idxerr == nil && idx.Count() == 0 {
			for k := range b.realArches {
				b.rt.dt.FS.DelDynamicTree(b.PathFor("", k))
			}
		}
	}
}

func AsBootEnv(o models.Model) *BootEnv {
	return o.(*BootEnv)
}

func AsBootEnvs(o []models.Model) []*BootEnv {
	res := make([]*BootEnv, len(o))
	for i := range o {
		res[i] = AsBootEnv(o[i])
	}
	return res
}

func (b *BootEnv) renderInfo() ([]models.TemplateInfo, []string) {
	return b.Templates, b.RequiredParams
}

func (b *BootEnv) templates() *template.Template {
	return b.rootTemplate
}

func (b *BootEnv) render(rt *RequestTracker, m *Machine, e models.ErrorAdder) renderers {
	r := newRenderData(rt, m, b)
	if m == nil {
		return r.makeRenderers(e)
	}
	res := renderers([]renderer{})
	toRender := r.validateRequiredParams(e)
	for i := range toRender {
		if strings.Contains(toRender[i].Path, `{{.Machine.MacAddr `) {
			for _, mac := range m.HardwareAddrs {
				r.Machine.currMac = mac
				res = r.addRenderer(e, &toRender[i], res)
			}
		} else {
			res = r.addRenderer(e, &toRender[i], res)
		}
	}
	return res
}

func (b *BootEnv) AfterSave() {
	rt := b.rt
	rt.RunAfter(func() {
		stages := rt.stores("stages")
		if stages != nil {
			rt.Debugf("BootEnv %s: Revalidating stages", b.Name)
			for _, i := range stages.Items() {
				stage := AsStage(i)
				rt.Tracef("BootEnv %s: Stage %s(%s)", b.Name, stage.Name, stage.BootEnv)
				if stage.BootEnv != b.Name {
					continue
				}
				rt.Debugf("BootEnv %s: Revalidating stage %s", b.Name, stage.Name)
				func() {
					rt.Tracef("Before: %#v", stage.Stage)
					stage.rt = rt
					defer func() { stage.rt = nil }()
					stage.ClearValidation()
					stage.Validate()
					rt.Tracef("After: %#v", stage.Stage)
				}()
			}
		}
	})
	if b.Available && b.renderers != nil {
		b.renderers.register(b.rt)
	}
	b.AddDynamicTree()
	b.renderers = nil
}

var bootEnvLockMap = map[string][]string{
	"get":     {"bootenvs"},
	"create":  {"stages:rw", "bootenvs:rw", "machines", "tasks", "templates:rw", "profiles", "params", "workflows:rw"},
	"update":  {"stages:rw", "bootenvs:rw", "machines", "tasks", "templates:rw", "profiles", "params", "workflows:rw"},
	"patch":   {"stages:rw", "bootenvs:rw", "machines", "tasks", "templates:rw", "profiles", "params", "workflows:rw"},
	"delete":  {"stages", "bootenvs:rw", "machines", "tasks", "templates", "profiles", "params"},
	"actions": {"stages", "bootenvs", "machines", "tasks", "templates", "profiles", "params"},
}

func (b *BootEnv) Locks(action string) []string {
	return bootEnvLockMap[action]
}
