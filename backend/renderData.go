package backend

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/VictorLowther/jsonpatch2/utils"
	"github.com/digitalrebar/provision/models"
	yaml "github.com/ghodss/yaml"
)

// Sizer is an interface for things that have Size.
type Sizer interface {
	Size() int64
}

// ReadSizer is an interface that has both a reader
// and can generate the size of that data.
type ReadSizer interface {
	io.Reader
	Sizer
}

type renderer struct {
	path, name string
	meta       map[string]string
	write      func(net.IP) (io.Reader, error)
}

func (r renderer) register(fs *FileSystem) {
	fs.AddDynamicFile(r.path, r.write)
}

func (r renderer) deregister(fs *FileSystem) {
	fs.DelDynamicFile(r.path)
}

type renderers []renderer

type renderable interface {
	models.Model
	renderInfo() ([]models.TemplateInfo, []string)
	templates() *template.Template
}

func (r renderers) register(fs *FileSystem) {
	if r == nil || len(r) == 0 {
		return
	}
	for _, rt := range r {
		rt.register(fs)
	}
}

func (r renderers) deregister(fs *FileSystem) {
	if r == nil || len(r) == 0 {
		return
	}
	for _, rt := range r {
		rt.deregister(fs)
	}
}

func newRenderedTemplate(r *RenderData,
	tmplKey,
	path string) renderer {
	var prefixes, keys []string
	if r.Task != nil {
		prefixes = append(prefixes, "tasks")
		keys = append(keys, r.Task.Key())
		r.rt.Debugf("Making renderer for %s:%s template %s at path %s", r.Task.Prefix(), r.Task.Key(), tmplKey, path)
	}
	if r.Stage != nil {
		prefixes = append(prefixes, "stages")
		keys = append(keys, r.Stage.Key())
		r.rt.Debugf("Making renderer for %s:%s template %s at path %s", r.Stage.Prefix(), r.Stage.Key(), tmplKey, path)
	}
	if r.Env != nil {
		prefixes = append(prefixes, "bootenvs")
		keys = append(keys, r.Env.Key())
		r.rt.Debugf("Making renderer for %s:%s template %s at path %s", r.Env.Prefix(), r.Env.Key(), tmplKey, path)
	}
	if r.Machine != nil {
		prefixes = append(prefixes, "machines")
		keys = append(keys, r.Machine.Key())
		r.rt.Debugf("Making renderer for %s:%s template %s at path %s", r.Machine.Prefix(), r.Machine.Key(), tmplKey, path)
	}
	targetPrefix := r.target.Prefix()
	dt := r.rt.dt
	return renderer{
		path: path,
		name: tmplKey,
		write: func(remoteIP net.IP) (io.Reader, error) {
			var err error
			rt := dt.Request(r.rt.Logger.Switch("bootenv"),
				"templates",
				"tasks",
				"stages",
				"bootenvs",
				"machines",
				"profiles",
				"params",
				"preferences")
			rd := &RenderData{rt: rt}
			rd.rt.Do(func(d Stores) {
				for i, prefix := range prefixes {
					item := rd.rt.find(prefix, keys[i])
					if item == nil {
						err = fmt.Errorf("%s:%s has vanished", prefix, keys[i])
					}
					switch obj := item.(type) {
					case *Task:
						rd.Task = &rTask{Task: obj, renderData: rd}
					case *Stage:
						rd.Stage = &rStage{Stage: obj, renderData: rd}
					case *BootEnv:
						rd.Env = &rBootEnv{BootEnv: obj, renderData: rd}
					case *Machine:
						rd.Machine = &rMachine{Machine: obj, renderData: rd}
					default:
						rd.rt.Errorf("%s:%s is neither Renderable nor a machine", prefix, keys[i])
						rd.rt.Panicf("Unrenderable Item: %#v", item)
					}
				}
			})
			if err != nil {
				return nil, err
			}
			switch targetPrefix {
			case "tasks":
				rd.target = renderable(rd.Task.Task)
			case "stages":
				rd.target = renderable(rd.Stage.Stage)
			case "bootenvs":
				rd.target = renderable(rd.Env.BootEnv)
			}
			rd.remoteIP = remoteIP
			rd.tmplKey = tmplKey
			rd.tmplPath = path
			buf := bytes.Buffer{}
			tmpl := rd.target.templates().Lookup(tmplKey)
			rd.rt.Do(func(d Stores) {
				err = tmpl.Execute(&buf, rd)
			})
			if err != nil {
				return nil, err
			}
			rd.rt.Debugf("Content:\n%s\n", string(buf.Bytes()))
			return bytes.NewReader(buf.Bytes()), nil
		},
	}
}

type rMachine struct {
	*Machine
	renderData *RenderData
	currMac    string
}

func (n *rMachine) Url() string {
	return n.renderData.rt.FileURL(n.renderData.remoteIP) + "/" + n.Path()
}

func (n *rMachine) MacAddr(params ...string) string {
	format := "raw"
	if len(params) > 0 {
		format = params[0]
	}
	switch format {
	case "pxelinux":
		return "01-" + strings.Replace(n.currMac, ":", "-", -1)
	default:
		return n.currMac
	}
}

type rBootEnv struct {
	*BootEnv
	renderData *RenderData
}

func (b *rBootEnv) arch() string {
	if b.renderData.Machine == nil {
		return "amd64"
	}
	return b.renderData.Machine.Arch
}

func (b *rBootEnv) KernelFor(arch string) string {
	return b.BootEnv.realArches[arch].Kernel
}

func (b *rBootEnv) Kernel() string {
	return b.KernelFor(b.arch())
}

func (b *rBootEnv) InitrdsFor(arch string) []string {
	return b.BootEnv.realArches[arch].Initrds
}

func (b *rBootEnv) Initrds() []string {
	return b.InitrdsFor(b.arch())
}

func (b *rBootEnv) BootParamsFor(arch string) (string, error) {
	params := b.BootEnv.realArches[arch].BootParams
	res := &bytes.Buffer{}
	tmpl, err := template.New("machine").Funcs(models.DrpSafeFuncMap()).Parse(params)
	if err != nil {
		return "", fmt.Errorf("Error compiling boot parameter template: %v", err)
	}
	tmpl = tmpl.Option("missingkey=error")
	if err := tmpl.Execute(res, b.renderData); err != nil {
		return "", err
	}
	str := res.String()
	// ipxe in uefi mode requires an initrd stanza in the boot params.
	// I have no idea why.
	if strings.HasSuffix(b.renderData.tmplPath, ".ipxe") {
		initrds := b.Initrds()
		if len(initrds) > 0 {
			str = fmt.Sprintf("initrd=%s %s", path.Base(initrds[0]), str)
		}
	}
	return str, nil
}

func (b *rBootEnv) BootParams() (string, error) {
	return b.BootParamsFor(b.arch())
}

// PathFor expands the partial paths for kernels and initrds into full
// paths appropriate for specific protocols.
//
// proto can be one of 3 choices:
//    http: Will expand to the URL the file can be accessed over.
//    tftp: Will expand to the path the file can be accessed at via TFTP.
//    disk: Will expand to the path of the file inside the provisioner container.
func (b *rBootEnv) PathForArch(proto, f, arch string) string {
	tail := b.BootEnv.PathFor(f, arch)
	switch proto {
	case "tftp":
		return strings.TrimPrefix(tail, "/")
	case "http":
		return b.renderData.rt.FileURL(b.renderData.remoteIP) + tail
	default:
		b.renderData.rt.Fatalf("Unknown protocol %v", proto)
	}
	return ""
}

func (b *rBootEnv) PathFor(proto, f string) string {
	return b.PathForArch(proto, f, b.arch())
}

// JoinInitrds joins the fully expanded initrd paths into a comma-separated string.
func (b *rBootEnv) JoinInitrdsFor(proto, arch string) string {
	fullInitrds := []string{}
	for _, initrd := range b.InitrdsFor(arch) {
		fullInitrds = append(fullInitrds, b.PathForArch(proto, initrd, arch))
	}
	return strings.Join(fullInitrds, " ")
}

func (b *rBootEnv) JoinInitrds(proto string) string {
	return b.JoinInitrdsFor(proto, b.arch())
}

type rTask struct {
	*Task
	renderData *RenderData
}

type rStage struct {
	*Stage
	renderData *RenderData
}

// Repo defines the repository structure used for
// the package-repositories parameter with additional
// fields to help rendering.
type Repo struct {
	Tag            string   `json:"tag"`
	OS             []string `json:"os"`
	Arch           string   `json:"arch"`
	URL            string   `json:"url"`
	PackageType    string   `json:"packageType"`
	RepoType       string   `json:"repoType"`
	InstallSource  bool     `json:"installSource"`
	SecuritySource bool     `json:"securitySource"`
	Distribution   string   `json:"distribution"`
	BootLoc        string   `json:"bootloc"`
	Components     []string `json:"components"`
	r              *RenderData
	targetOS       string
}

// JoinedComponents returns the Components array as
// a single string joined with spaces.
func (rd *Repo) JoinedComponents() string {
	return strings.Join(rd.Components, " ")
}

// R returns the RenderData for this repo.
func (rd *Repo) R() *RenderData {
	return rd.r
}

// Target returns the target os for this Repo.
func (rd *Repo) Target() string {
	return rd.targetOS
}

func (rd *Repo) osParts() (string, string) {
	parts := strings.SplitN(rd.targetOS, "-", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return rd.targetOS, ""
}

func (rd *Repo) renderStyle() string {
	if rd.RepoType != "" {
		return rd.RepoType
	}
	osName, _ := rd.osParts()
	switch osName {
	case "redhat", "rhel", "centos", "scientificlinux":
		return "yum"
	case "suse", "sles", "opensuse":
		return "zypp"
	case "debian", "ubuntu":
		return "apt"
	default:
		return "unknown"
	}
}

// UrlFor returns a Url for the requested component part of the repo.
func (rd *Repo) UrlFor(component string) string {
	if rd.InstallSource || rd.Distribution == "" || component == "" {
		return rd.URL
	}
	osName, _ := rd.osParts()
	switch osName {
	case "centos":
		return fmt.Sprintf("%s/%s/%s/$basearch", rd.URL, rd.Distribution, component)
	case "scientificlinux":
		return fmt.Sprintf("%s/%s/$basearch/%s", rd.URL, rd.Distribution, component)
	default:
		return rd.URL
	}
}

// Install returns a string or the encountered error that
// represents the package repo type specific file snippets
// for either preseed/kickstarts with parts for either
// the core install part or updates/additional repos.
func (rd *Repo) Install() (string, error) {
	tmpl := template.New("installLines").Funcs(models.DrpSafeFuncMap()).Option("missingkey=error")
	var err error
	toExec := &bytes.Buffer{}
	switch rd.renderStyle() {
	case "yum":
		if rd.InstallSource {
			fmt.Fprintf(toExec, `install
url --url %s
repo --name="{{.Tag}}" --baseurl=%s --cost=100{{if .R.ParamExists "proxy-servers"}} --proxy="{{index (.R.Param "proxy-servers") 0}}"{{end}}
`,
				rd.URL, rd.URL)
		} else if len(rd.Components) == 0 {
			fmt.Fprintf(toExec, `repo --name="{{.Tag}}" --baseurl=%s --cost=200{{if .R.ParamExists "proxy-servers"}} --proxy="{{index (.R.Param "proxy-servers") 0}}"{{end}}
`,
				rd.URL)
		} else {
			for _, component := range rd.Components {
				fmt.Fprintf(toExec, `repo --name="{{.Tag}}-%s" --baseurl=%s --cost=200{{if .R.ParamExists "proxy-servers"}} --proxy="{{index (.R.Param "proxy-servers") 0}}"{{end}}
`,
					component, rd.UrlFor(component))
			}
		}
	case "apt":
		if rd.InstallSource {
			fmt.Fprintln(toExec, `d-i mirror/protocol string {{.R.ParseUrl "scheme" .URL}}
d-i mirror/http/hostname string {{.R.ParseUrl "host" .URL}}
d-i mirror/http/directory string {{.R.ParseUrl "path" .URL}}`)
		} else {
			fmt.Fprintln(toExec, `{{if (eq "debian" .R.Env.OS.Family)}}
d-i apt-setup/security_host string {{.URL}}
{{else}}
d-i apt-setup/security_host string {{.R.ParseUrl "host" .URL}}
d-i apt-setup/security_path string {{.R.ParseUrl "path" .URL}}
{{end}}`)
		}
	default:
		return "", fmt.Errorf("No idea how to handle repos for %s", rd.targetOS)
	}
	tmpl, err = tmpl.Parse(toExec.String())
	if err != nil {
		return "", err
	}
	buf := &bytes.Buffer{}
	err = tmpl.Execute(buf, rd)
	return buf.String(), err
}

// Lines returns an error or the string for inclusion in a
// configuration file in the package manager specific format
// based upon the repo definitions.
func (rd *Repo) Lines() (string, error) {
	tmpl := template.New("installLines").Funcs(models.DrpSafeFuncMap()).Option("missingkey=error")
	var err error
	switch rd.renderStyle() {
	case "yum":
		tmpl, err = tmpl.Parse(`{{range $component := $.Components}}
[{{$.Tag}}-{{$component}}]
name={{$.Tag}} - {{$component}}
baseurl={{$.UrlFor $component}}
gpgcheck=0
{{else}}
[{{$.Tag}}]
name={{$.Target}} - {{$.Tag}}
baseurl={{$.UrlFor ""}}
gpgcheck=0
{{ end }}`)
	case "apt":
		tmpl, err = tmpl.Parse(`deb {{.URL}} {{.Distribution}} {{.JoinedComponents}}
`)
	default:
		return "", fmt.Errorf("No idea how to handle repos for %s", rd.targetOS)
	}
	if err != nil {
		return "", err
	}
	buf := &bytes.Buffer{}
	err = tmpl.Execute(buf, rd)
	return buf.String(), err
}

// InstallUrl for returns an error or the string representing how
// to access the install parts of this specified BootEnv.
func (b *rBootEnv) InstallUrl() (string, error) {
	repos := b.renderData.InstallRepos()
	if len(repos) == 0 {
		return "", fmt.Errorf("No install repository available")
	}
	return repos[0].URL, nil
}

// RenderData is the struct that is passed to templates as a source of
// parameters and useful methods.
type RenderData struct {
	Machine           *rMachine // The Machine that the template is being rendered for.
	Env               *rBootEnv // The boot environment that provided the template.
	Task              *rTask
	Stage             *rStage
	rt                *RequestTracker
	target            renderable
	tmplKey, tmplPath string
	remoteIP          net.IP
}

func (r *RenderData) fetchRepos(test func(*Repo) bool) (res []*Repo) {
	res = []*Repo{}
	p, err := r.Param("package-repositories")
	if p == nil || err != nil {
		return
	}
	repos := []*Repo{}
	if utils.Remarshal(p, &repos) != nil {
		return
	}
	for _, repo := range repos {
		if !test(repo) {
			continue
		}
		repo.r = r
		res = append(res, repo)
	}
	return
}

// Repos is a template helper function that returns an array
// of all the appropriate repos based upon the tag list.
func (r *RenderData) Repos(tags ...string) []*Repo {
	return r.fetchRepos(func(rd *Repo) bool {
		for _, t := range tags {
			if t == rd.Tag {
				return true
			}
		}
		return false
	})
}

func (r *RenderData) localInstallRepo() *Repo {
	for _, obj := range r.rt.d("bootenvs").Items() {
		env := obj.(*BootEnv)
		r.rt.Debugf("Examining env %s for machine %s OS %s", env.Name, r.Machine.UUID(), r.Machine.OS)
		if env.OS.Name == r.Machine.OS && env.canLocalBoot(r.rt, r.Machine.Arch) == nil {
			res := &Repo{
				Tag:           env.Name,
				InstallSource: true,
				OS:            []string{r.Machine.OS},
				URL:           r.rt.FileURL(r.remoteIP) + env.PathFor("", r.Machine.Arch),
				r:             r,
				targetOS:      r.Machine.OS,
			}

			switch res.renderStyle() {
			case "apt":
				if _, err := os.Stat(path.Join(r.rt.dt.FileRoot, r.Machine.OS, "install", "dists", "stable", "Release")); err == nil {
					res.Distribution = "stable"
					res.Components = []string{"main", "restricted"}
				} else {
					continue
				}
			}
			return res
		}
	}
	return nil
}

// MachineRepos returns a list of the repos for the specific machine's
// current state.
func (r *RenderData) MachineRepos() []*Repo {
	found := []*Repo{}
	// Sigh, current ubuntus do not have metadata good enough for things besides
	// OS installation.
	li := r.localInstallRepo()
	if li != nil && li.renderStyle() != "apt" {
		found = append(found, li)
	}
	found = append(found, r.fetchRepos(func(rd *Repo) bool {
		if li != nil && rd.InstallSource {
			return false
		}
		ok := rd.Arch == "any" && !rd.InstallSource
		if !ok {
			a1, a1ok := models.SupportedArch(rd.Arch)
			if !a1ok {
				return false
			}
			a2, _ := models.SupportedArch(r.Machine.Arch)
			ok = a1 == a2
		}
		if !ok {
			return false
		}
		for _, os := range rd.OS {
			if os == r.Machine.OS {
				rd.targetOS = r.Machine.OS
				return true
			}
		}
		return false
	})...)

	return found
}

// InstallRepos returns a list of repos for the base
// install of the current machine bootenv combo.  The
// first repo is the install source.  The second repo
// is the security update repo.
func (r *RenderData) InstallRepos() []*Repo {
	installRepo := r.localInstallRepo()
	found := r.MachineRepos()
	var updateRepo *Repo
	res := []*Repo{}
	for _, repo := range found {
		if installRepo == nil && repo.InstallSource {
			installRepo = repo
		}
		if updateRepo == nil && repo.SecuritySource {
			updateRepo = repo
		}
	}
	if installRepo != nil {
		res = append(res, installRepo)
		if updateRepo != nil {
			res = append(res, updateRepo)
		}
	}
	return res
}

func newRenderData(rt *RequestTracker, m *Machine, r renderable) *RenderData {
	res := &RenderData{rt: rt}
	res.target = r
	if m != nil {
		res.Machine = &rMachine{Machine: m, renderData: res}
	}
	switch obj := r.(type) {
	case *BootEnv:
		res.Env = &rBootEnv{BootEnv: obj, renderData: res}
	case *Task:
		res.Task = &rTask{Task: obj, renderData: res}
	case *Stage:
		res.Stage = &rStage{Stage: obj, renderData: res}
	}
	if m != nil {
		if res.Env == nil {
			obj := rt.find("bootenvs", m.BootEnv)
			if obj != nil {
				res.Env = &rBootEnv{BootEnv: obj.(*BootEnv), renderData: res}
			}
		}
		if res.Stage == nil {
			obj := rt.find("stages", m.Stage)
			if obj != nil {
				res.Stage = &rStage{Stage: obj.(*Stage), renderData: res}
			}
		}
	}
	return res
}

// ProvisionerAddress returns the IP address to access
// the Provisioner based upon the requesting IP address.
func (r *RenderData) ProvisionerAddress() string {
	return r.rt.dt.LocalIP(r.remoteIP)
}

// ProvisionerURL returns a URL to access the
// file server part of the server using the
// requesting IP address as a basis.
func (r *RenderData) ProvisionerURL() string {
	return r.rt.FileURL(r.remoteIP)
}

// ApiURL returns a URL to access the
// api server part of the server using the
// requesting IP address as a basis.
func (r *RenderData) ApiURL() string {
	return r.rt.ApiURL(r.remoteIP)
}

// GenerateToken will generate a token for a machine
// within a template.  If the machine is not known, a
// token will be generate with create machine access only
// with a time limited by the unknownTokenTimeout preference.
// If the machine is known, a token will be generated with
// machine update access for the specific machine with a time
// limited by the knownTokenTimeout preference.  The token
// is granted by the system with and signed with the system
// grantor secret.
func (r *RenderData) GenerateToken() string {
	var t string

	grantor := "system"
	grantorSecret := ""
	if ss := r.rt.dt.pref("systemGrantorSecret"); ss != "" {
		grantorSecret = ss
	}

	if r.Machine == nil {
		ttl := time.Minute * 10
		if sttl := r.rt.dt.pref("unknownTokenTimeout"); sttl != "" {
			mttl, _ := strconv.Atoi(sttl)
			ttl = time.Second * time.Duration(mttl)
		}
		t, _ = NewClaim("general", grantor, ttl).
			AddRawClaim("machines", "create", "*").
			AddRawClaim("machines", "get", "*").
			AddSecrets("", grantorSecret, "").
			Seal(r.rt.dt.tokenManager)
	} else {
		ttl := time.Hour
		if sttl := r.rt.dt.pref("knownTokenTimeout"); sttl != "" {
			mttl, _ := strconv.Atoi(sttl)
			ttl = time.Second * time.Duration(mttl)
		}
		t, _ = NewClaim(r.Machine.Key(), grantor, ttl).
			AddRawClaim("machines", "get, actions, update, patch, action, getSecure, updateSecure", r.Machine.Key()).
			AddRawClaim("params", "get", "*").
			AddRawClaim("stages", "get", "*").
			AddRawClaim("jobs", "create", r.Machine.Key()).
			AddRawClaim("jobs", "get", r.Machine.Key()).
			AddRawClaim("jobs", "update", r.Machine.Key()).
			AddRawClaim("jobs", "actions", r.Machine.Key()).
			AddRawClaim("jobs", "log", r.Machine.Key()).
			AddRawClaim("tasks", "get", "*").
			AddRawClaim("info", "get", "*").
			AddRawClaim("events", "post", "*").
			AddRawClaim("reservations", "create", "*").
			AddRawClaim("reservations", "*", models.Hexaddr(r.Machine.Address)).
			AddMachine(r.Machine.Key()).
			AddSecrets("", grantorSecret, r.Machine.Secret).
			Seal(r.rt.dt.tokenManager)
	}
	return t
}

// GenerateInfiniteToken generates a token for a specific machine
// that has a three year timeout.  It has the same permissions
// as the token generated by GenerateToken for a known machine.
func (r *RenderData) GenerateInfiniteToken() string {
	if r.Machine == nil {
		// Don't allow infinite tokens.
		return ""
	}

	grantor := "system"
	grantorSecret := ""
	if ss := r.rt.dt.pref("systemGrantorSecret"); ss != "" {
		grantorSecret = ss
	}

	ttl := time.Hour * 24 * 7 * 52 * 3
	t, _ := NewClaim(r.Machine.Key(), grantor, ttl).
		AddRawClaim("machines", "get, actions, update, patch, action, getSecure, updateSecure", r.Machine.Key()).
		AddRawClaim("params", "get", "*").
		AddRawClaim("stages", "get", "*").
		AddRawClaim("jobs", "create", r.Machine.Key()).
		AddRawClaim("jobs", "get", r.Machine.Key()).
		AddRawClaim("jobs", "update", r.Machine.Key()).
		AddRawClaim("jobs", "actions", r.Machine.Key()).
		AddRawClaim("jobs", "log", r.Machine.Key()).
		AddRawClaim("tasks", "get", "*").
		AddRawClaim("info", "get", "*").
		AddRawClaim("events", "post", "*").
		AddRawClaim("reservations", "create", "*").
		AddRawClaim("reservations", "*", models.Hexaddr(r.Machine.Address)).
		AddMachine(r.Machine.Key()).
		AddSecrets("", grantorSecret, r.Machine.Secret).
		Seal(r.rt.dt.tokenManager)
	return t
}

// GenerateProfileToken will generate a token that has access to
// read and update the specified token for a set duration.  If
// duration is 0, then duration is 2000000000 seconds.
// This is used for atomic profile operations for cluster management.
func (r *RenderData) GenerateProfileToken(profile string, duration int) string {
	if r.Machine == nil {
		// Don't allow profile tokens.
		return "UnknownMachineTokenNotAllowed"
	}

	if !r.Machine.HasProfile(profile) {
		// Don't allow profile tokens.
		return "InvalidTokenNotAllowedNotOnMachine"
	}

	if p := r.rt.find("profiles", profile); p == nil {
		// Don't allow profile tokens.
		return "InvalidTokenNotAllowedNoProfile"
	}

	grantor := "system"
	grantorSecret := ""
	if ss := r.rt.dt.pref("systemGrantorSecret"); ss != "" {
		grantorSecret = ss
	}

	if duration <= 0 {
		duration = 2000000000
	}
	ttl := time.Second * time.Duration(duration)

	t, _ := NewClaim(r.Machine.Key(), grantor, ttl).
		AddRawClaim("profiles", "get", profile).
		AddRawClaim("profiles", "update", profile).
		AddRawClaim("params", "get", "*").
		AddMachine(r.Machine.Key()).
		AddSecrets("", grantorSecret, r.Machine.Secret).
		Seal(r.rt.dt.tokenManager)
	return t
}

// BootParams is a helper function that expands the BootParams
// template from the boot environment.
func (r *RenderData) BootParamsFor(arch string) (string, error) {
	if r.Env == nil {
		return "", fmt.Errorf("Missing bootenv")
	}
	return r.Env.BootParamsFor(arch)
}
func (r *RenderData) BootParams() (string, error) {
	if r.Env == nil {
		return "", fmt.Errorf("Missing bootenv")
	}
	return r.BootParamsFor(r.Env.arch())
}

// ParseUrl is a template function that return the section
// of the specified URL as a string.
func (r *RenderData) ParseUrl(segment, rawUrl string) (string, error) {
	parsedUrl, err := url.Parse(rawUrl)
	if err != nil {
		return "", err
	}
	switch segment {
	case "scheme":
		return parsedUrl.Scheme, nil
	case "host":
		return parsedUrl.Host, nil
	case "path":
		return parsedUrl.Path, nil
	}
	return "", fmt.Errorf("No idea how to get URL part %s from %s", segment, rawUrl)
}

// Param is a helper function for extracting a parameter from Machine.Params
func (r *RenderData) Param(key string) (interface{}, error) {
	if r.Machine != nil {
		v, ok := r.rt.GetParam(r.Machine, key, true, r.Task != nil)
		if ok {
			return v, nil
		}
	}
	if o := r.rt.find("profiles", r.rt.dt.GlobalProfileName); o != nil {
		p := AsProfile(o)
		if v, ok := r.rt.GetParam(p, key, true, r.Task != nil); ok {
			return v, nil
		}
	}
	return nil, fmt.Errorf("No such machine parameter %s", key)
}

// ParamAsJSON will return the specified parameter as a JSON
// string or an error.
func (r *RenderData) ParamAsJSON(key string) (string, error) {
	v, err := r.Param(key)
	if err != nil {
		return "", err
	}
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	err = enc.Encode(v)
	return buf.String(), err
}

// ParamAsYAML will return the specified parameter as a YAML
// string or an error.
func (r *RenderData) ParamAsYAML(key string) (string, error) {
	v, err := r.Param(key)
	if err != nil {
		return "", err
	}
	b, e := yaml.Marshal(v)
	if e != nil {
		return "", e
	}
	return string(b), nil
}

// ParamExists is a helper function for determining the existence of a machine parameter.
func (r *RenderData) ParamExists(key string) bool {
	_, err := r.Param(key)
	return err == nil
}

// CallTemplate allows for sub-templating like the template function, but
// allows for function expansion of the arguments unlike the built-in
// template function.
func (r *RenderData) CallTemplate(name string, data interface{}) (ret interface{}, err error) {
	buf := bytes.NewBuffer([]byte{})
	tmpl := r.target.templates().Lookup(name)
	if tmpl == nil {
		return nil, fmt.Errorf("Missing template: %s", name)
	}
	err = tmpl.Execute(buf, data)
	if err == nil {
		ret = buf.String()
	}
	return
}

func (r *RenderData) validateRequiredParams(e models.ErrorAdder) []models.TemplateInfo {
	toRender, requiredParams := r.target.renderInfo()
	for _, param := range requiredParams {
		if !r.ParamExists(param) {
			e.Errorf("Missing required parameter %s for %s %s", param, r.target.Prefix(), r.target.Key())
		}
	}
	return toRender
}

func (r *RenderData) addRenderer(e models.ErrorAdder, ti *models.TemplateInfo, rts renderers) renderers {
	tmplPath := ""
	if ti.PathTemplate() != nil {
		// first, render the path
		buf := &bytes.Buffer{}
		if err := ti.PathTemplate().Execute(buf, r); err != nil {
			e.Errorf("Error rendering template %s path %s: %v",
				ti.Name,
				ti.Path,
				err)
			return rts
		}
		if r.target.Prefix() == "tasks" {
			tmplPath = path.Clean(buf.String())
		} else {
			tmplPath = path.Clean("/" + buf.String())
		}
	}
	rt := newRenderedTemplate(r, ti.Id(), tmplPath)
	rt.meta = ti.Meta
	return append(rts, rt)
}

func (r *RenderData) makeRenderers(e models.ErrorAdder) renderers {
	tmpls := r.validateRequiredParams(e)
	rts := renderers([]renderer{})
	for i := range tmpls {
		rts = r.addRenderer(e, &tmpls[i], rts)
	}
	return rts
}
