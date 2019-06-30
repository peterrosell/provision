package backend

import (
	"io/ioutil"
	"net"
	"path"
	"testing"

	"github.com/digitalrebar/provision/models"
	"github.com/pborman/uuid"
)

const (
	tmplIncluded = `Machine: 
{{ "hello!" | upper | repeat 5 }}
Name = {{.Machine.Name}}
HexAddress = {{.Machine.HexAddress}}
ShortName = {{.Machine.ShortName}}
FooParam = {{.Param "foo"}}
ExpandParamNoExpand = {{.Param "fooExpand"}}
ExpandParam = {{.ParamExpand "fooExpand"}}`

	tmplDefault = `{{template "included" .}}

BootEnv:
Name = {{.Env.Name}}

{{if .ParamExists "fred"}}{{.Param "fred"}}{{end}}

{{if .ParamExists "obj" -}}
{{.ParamAsJSON "obj"}}

{{.ParamAsYAML "obj"}}
{{end -}}

RenderData:
ProvisionerAddress = {{.ProvisionerAddress}}
ProvisionerURL = {{.ProvisionerURL}}
ApiURL = {{.ApiURL}}`
	tmplDefaultRenderedWithoutFred = `Machine: 
HELLO!HELLO!HELLO!HELLO!HELLO!
Name = Test Name
HexAddress = C0A87C0B
ShortName = Test Name
FooParam = bar
ExpandParamNoExpand = bar{{.ProvisionerURL}}
ExpandParam = barhttp://127.0.0.1:8091

BootEnv:
Name = default



RenderData:
ProvisionerAddress = 127.0.0.1
ProvisionerURL = http://127.0.0.1:8091
ApiURL = https://127.0.0.1:8092`
	tmplDefaultRenderedWithFred = `Machine: 
HELLO!HELLO!HELLO!HELLO!HELLO!
Name = Test Name
HexAddress = C0A87C0B
ShortName = Test Name
FooParam = bar
ExpandParamNoExpand = bar{{.ProvisionerURL}}
ExpandParam = barhttp://127.0.0.1:8091

BootEnv:
Name = default

fred = fred

{"Title":"title","Value":40}


Title: title
Value: 40

RenderData:
ProvisionerAddress = 127.0.0.1
ProvisionerURL = http://127.0.0.1:8091
ApiURL = https://127.0.0.1:8092`
	tmplNothing = `Nothing`

	tmplFail1 = `{{ ago }}`
	tmplFail2 = `{{ now }}`
	tmplFail3 = `{{ env }}`
	tmplFail4 = `{{ expandenv }}`
)

func TestRenderData(t *testing.T) {
	dt := mkDT()
	rt := dt.Request(dt.Logger,
		"stages:rw",
		"bootenvs:rw",
		"templates:rw",
		"machines:rw",
		"profiles:rw",
		"params:rw",
		"tasks:rw",
		"preferences:rw",
		"workflows:rw")
	claimrt := dt.Request(dt.Logger, "roles")
	var machine *Machine
	var paramWithDefault *Param
	var defaultBootEnv, nothingBootEnv, badBootEnv *BootEnv
	rt.Do(func(d Stores) {
		paramWithDefault = AsParam(toBackend(&models.Param{
			Name: "withDefault",
			Schema: map[string]interface{}{
				"type":    "string",
				"default": "default",
			},
		}, rt))
		defaultBootEnv = AsBootEnv(toBackend(
			&models.BootEnv{
				Name: "default",
				Templates: []models.TemplateInfo{
					{
						Name: "ipxe",
						Path: "machines/{{.Machine.UUID}}/file",
						ID:   "default",
					},
					{
						Name: "ipxe-mac",
						Path: "machines/{{.Machine.UUID}}/{{.Machine.MacAddr \"ipxe\"}}",
						ID:   "default",
					},
				},
			},
			rt))
		nothingBootEnv = AsBootEnv(toBackend(&models.BootEnv{
			Name: "nothing",
			Templates: []models.TemplateInfo{
				{
					Name: "ipxe",
					Path: "machines/{{.Machine.UUID}}/file",
					ID:   "nothing",
				},
			},
		},
			rt))
		badBootEnv = AsBootEnv(toBackend(&models.BootEnv{
			Name: "bad",
			Templates: []models.TemplateInfo{
				{
					Name: "ipxe",
					Path: "machines/{{.Machine.UUID}}/file",
					ID:   "nothing",
				},
			},
		}, rt))
	})
	objs := []crudTest{
		{"Update global profile to have test with a value", rt.Update, &models.Profile{Name: "global", Params: map[string]interface{}{"test": "foreal"}}, true},
		{"create test profile to have test with a value", rt.Create, &models.Profile{Name: "test", Params: map[string]interface{}{"test": "fred"}}, true},

		{"Create included template", rt.Create, &models.Template{ID: "included", Contents: tmplIncluded}, true},
		{"Create default template", rt.Create, &models.Template{ID: "default", Contents: tmplDefault}, true},
		{"Create nothing template", rt.Create, &models.Template{ID: "nothing", Contents: tmplNothing}, true},
		{"Fail to render fail1", rt.Create, &models.Template{ID: "fail1", Contents: tmplFail1}, false},
		{"Fail to render fail2", rt.Create, &models.Template{ID: "fail2", Contents: tmplFail2}, false},
		{"Fail to render fail3", rt.Create, &models.Template{ID: "fail3", Contents: tmplFail3}, false},
		{"Fail to render fail4", rt.Create, &models.Template{ID: "fail4", Contents: tmplFail4}, false},
		{"Create default bootenv", rt.Create, defaultBootEnv, true},
		{"Create nothing bootenv", rt.Create, nothingBootEnv, true},
		{"Create bad bootenv", rt.Create, badBootEnv, true},
		{"Create param with default", rt.Create, paramWithDefault, true},
	}
	for _, obj := range objs {
		obj.Test(t, rt)
	}
	machine = &Machine{}
	Fill(machine)
	machine.Uuid = uuid.NewRandom()
	machine.Name = "Test Name"
	machine.Address = net.ParseIP("192.168.124.11")
	machine.BootEnv = "default"
	machine.HardwareAddrs = []string{"3c:a9:f4:31:57:98", "f0:1f:af:17:f0:9a"}
	rt.Do(func(d Stores) {
		created, err := rt.Create(machine)
		if !created {
			t.Errorf("Failed to create new test machine: %v", err)
			return
		}
		t.Logf("Created new test machine")
		machine.Params["foo"] = "bar"
		machine.Params["fooExpand"] = "bar{{.ProvisionerURL}}"
		machine.Params["fooBadExpand"] = "bar{{.ProvisionerURL"
		machine.Params["fooBadExpand2"] = "bar{{.PrionerURL}}"
		rt.Save(machine)
	})
	genLocs := []string{
		path.Join("/", "machines", machine.UUID(), "file"),
		path.Join("/", "machines", machine.UUID(), machine.HardwareAddrs[0]),
		path.Join("/", "machines", machine.UUID(), machine.HardwareAddrs[1]),
	}
	for _, genLoc := range genLocs {
		out, err := dt.FS.Open(genLoc, nil)
		if err != nil || out == nil {
			t.Errorf("Failed to get template for %s: %v\n%#v", genLoc, err, out)
			return
		}
		buf, err := ioutil.ReadAll(out)
		if err != nil {
			t.Errorf("Failed to read %s: %v", genLoc, err)
		} else if string(buf) != tmplDefaultRenderedWithoutFred {
			t.Errorf("Failed to render expected template!\nExpected:\n%s\n\nGot:\n%s", tmplDefaultRenderedWithoutFred, string(buf))
		} else {
			t.Logf("BootEnv default without fred rendered properly for test machine")
		}
	}
	rt.Do(func(d Stores) {
		obj := struct {
			Title string
			Value int
		}{
			"title",
			40,
		}
		machine.Params["obj"] = obj
		machine.Params["fred"] = "fred = fred"
		rt.Save(machine)
	})
	genLoc := path.Join("/", "machines", machine.UUID(), "file")
	out, err := dt.FS.Open(genLoc, nil)
	if err != nil {
		t.Errorf("Failed to get tmeplate for %s: %v", genLoc, err)
	}
	buf, err := ioutil.ReadAll(out)
	if err != nil {
		t.Errorf("Failed to read %s: %v", genLoc, err)
	} else if string(buf) != tmplDefaultRenderedWithFred {
		t.Errorf("Failed to render expected template!\nExpected:\n%s\n\nGot:\n%s", tmplDefaultRenderedWithFred, string(buf))
	} else {
		t.Logf("BootEnv default with fred rendered properly for test machine")
	}
	rt.Do(func(d Stores) {
		dbgPref := rt.dt.pref("logLevel")
		rt.dt.SetPrefs(rt, map[string]string{"logLevel": "trace", "debugRenderer": "trace", "debugBootEnv": "trace"})
		machine.BootEnv = "nothing"
		saved, err := rt.Save(machine)
		if !saved || err != nil {
			t.Errorf("Failed to save test machine with new bootenv: %v", err)
		}
		if machine.HasError() != nil {
			t.Errorf("Machine error: %v", machine.HasError())
		}
		rt.dt.SetPrefs(rt, map[string]string{"logLevel": dbgPref, "debugRenderer": dbgPref, "debugBootEnv": dbgPref})
	})
	out, err = dt.FS.Open(genLoc, nil)
	if err != nil {
		t.Errorf("Failed to get template for %s: %v", genLoc, err)
	}
	buf, err = ioutil.ReadAll(out)
	if err != nil {
		t.Errorf("Failed to read %s: %v", genLoc, err)
	} else if string(buf) != tmplNothing {
		t.Errorf("Failed to render expected template!\nExpected:\n%s\n\nGot:\n%s", tmplNothing, string(buf))
	} else {
		t.Logf("BootEnv nothing rendered properly for test machine")
	}
	rt.Do(func(d Stores) {
		var s string
		// Test the render functions directly.
		rd := newRenderData(rt, nil, nil)
		// Test ParseUrl - independent of Machine and Env
		_, e := rd.ParseUrl("scheme", "http://192.168.0.%31:8080/")
		if e == nil {
			t.Errorf("ParseUrl with bad URL should have generated an error\n")
		} else if e.Error() != "parse http://192.168.0.%31:8080/: invalid URL escape \"%31\"" {
			t.Errorf("ParseUrl with bad URL should have generated an error: %s, but got %s\n", "parse http://192.168.0.%31:8080/: invalid URL escape \"%31\"", e.Error())
		}
		_, e = rd.ParseUrl("bogus", "https://fred/path/apt")
		if e == nil {
			t.Errorf("ParseUrl with bad segment should have generated an error\n")
		} else if e.Error() != "No idea how to get URL part bogus from https://fred/path/apt" {
			t.Errorf("ParseUrl with bad segment should have generated an error: %s, but got %s\n", "No idea how to get URL part bogus from https://fred/path/apt", e.Error())
		}
		s, e = rd.ParseUrl("scheme", "https://fred/path/apt")
		if e != nil {
			t.Errorf("ParseUrl with scheme segment should NOT have generated an error: %v\n", e)
		}
		if s != "https" {
			t.Errorf("ParseUrl with scheme segment found incorrect scheme: %s, %s\n", "https", s)
		}
		s, e = rd.ParseUrl("host", "https://fred/path/apt")
		if e != nil {
			t.Errorf("ParseUrl with host segment should NOT have generated an error: %v\n", e)
		}
		if s != "fred" {
			t.Errorf("ParseUrl with host segment found incorrect host: %s, %s\n", "fred", s)
		}
		s, e = rd.ParseUrl("path", "https://fred/path/apt")
		if e != nil {
			t.Errorf("ParseUrl with path segment should NOT have generated an error: %v\n", e)
		}
		if s != "/path/apt" {
			t.Errorf("ParseUrl with path segment found incorrect path: %s, %s\n", "/path/apt", s)
		}

		// Test other functions - without a machine or env
		_, e = rd.Param("bogus")
		if e == nil {
			t.Errorf("Param should return an error when machine is not and not global defined in RenderData\n")
		} else if e.Error() != "No such machine parameter bogus" {
			t.Errorf("Param should return an error: No such machine parameter bogus, but returned: %s\n", e.Error())
		}
		ok := rd.ParamExists("bogus")
		if ok {
			t.Errorf("ParamExists should return false when machine is not defined and not global in RenderData\n")
		}
		// Test global parameter
		p, e := rd.Param("test")
		if e != nil {
			t.Errorf("Param test should NOT return an error: %v\n", e)
		}
		s, ok = p.(string)
		if !ok {
			t.Errorf("Parameter test should have been a string\n")
		} else {
			if s != "foreal" {
				t.Errorf("Parameter test should have been foreal: %s\n", s)
			}
		}
		ok = rd.ParamExists("test")
		if !ok {
			t.Errorf("ParamExists test should return true when machine has foo defined in RenderData\n")
		}
		// Test a parameter with a default value embedded in the schema
		p, e = rd.Param("withDefault")
		if e != nil {
			t.Errorf("Param withDefault should NOT return an error: %v", e)
		}
		s, ok = p.(string)
		if !ok {
			t.Errorf("Parameter test with default should have been a string")
		} else if s != "default" {
			t.Errorf("Parameter test with default should have been `default`m not `%v`", s)
		}

		_, e = rd.BootParams()
		if e == nil {
			t.Errorf("BootParams with no ENV should have generated an error\n")
		} else if e.Error() != "Missing bootenv" {
			t.Errorf("BootParams with no ENV should have generated an error: %s, but got %s\n", "Missing bootenv", e.Error())
		}

		grantorSecret, _ := dt.Pref("systemGrantorSecret")

		s = rd.GenerateToken()
		claim, e := dt.GetToken(s)
		if e != nil {
			t.Errorf("GetToken should return a good claim. %v\n", e)
		}
		if !claim.match(claimrt, models.MakeRole("", "machines", "create", "anything")) {
			t.Errorf("Unknown token should match: machines/create/*\n")
		}
		if !claim.match(claimrt, models.MakeRole("", "machines", "get", "anything")) {
			t.Errorf("Unknown token should match: machines/get/*\n")
		}
		if claim.ExpiresAt-claim.IssuedAt != 600 {
			t.Errorf("Unknown token timeout should be 600, but was %v\n", claim.ExpiresAt-claim.IssuedAt)
		}
		if !claim.ValidateSecrets(grantorSecret, "", "") {
			t.Errorf("Secrets validate to validate correctly: %s %s",
				grantorSecret, claim.GrantorClaims.GrantorSecret)
		}
		if !claim.ValidateSecrets(grantorSecret, "empty", "empty") {
			t.Errorf("Secrets validate to validate correctly: %s %s",
				grantorSecret, claim.GrantorClaims.GrantorSecret)
		}
		if claim.ValidateSecrets(grantorSecret+"1", "", "") {
			t.Errorf("Secrets validate should not validate correctly: %s %s",
				grantorSecret+"1", claim.GrantorClaims.GrantorSecret)
		}
		e = dt.SetPrefs(rt, map[string]string{"unknownTokenTimeout": "50"})
		if e != nil {
			t.Errorf("SetPrefs should not return an error: %v\n", e)
		}
		s = rd.GenerateToken()
		claim, e = dt.GetToken(s)
		if e != nil {
			t.Errorf("GetToken should return a good claim. %v\n", e)
		}
		if !claim.match(claimrt, models.MakeRole("", "machines", "create", "anything")) {
			t.Errorf("Unknown token should match: machines/create/*\n")
		}
		if !claim.match(claimrt, models.MakeRole("", "machines", "get", "anything")) {
			t.Errorf("Unknown token should match: machines/get/*\n")
		}
		if claim.match(claimrt, models.MakeRole("", "machines", "update", "anything")) {
			t.Errorf("Unknown token should NOT match: machines/update/*\n")
		}
		if claim.ExpiresAt-claim.IssuedAt != 50 {
			t.Errorf("Unknown token timeout should be 50, but was %v\n", claim.ExpiresAt-claim.IssuedAt)
		}
		if !claim.ValidateSecrets(grantorSecret, "", "") {
			t.Errorf("Secrets validate to validate correctly: %s %s",
				grantorSecret, claim.GrantorClaims.GrantorSecret)
		}
		if !claim.ValidateSecrets(grantorSecret, "empty", "empty") {
			t.Errorf("Secrets validate to validate correctly: %s %s",
				grantorSecret, claim.GrantorClaims.GrantorSecret)
		}
		if claim.ValidateSecrets(grantorSecret+"1", "", "") {
			t.Errorf("Secrets validate should not validate correctly: %s %s",
				grantorSecret+"1", claim.GrantorClaims.GrantorSecret)
		}
		s = rd.GenerateInfiniteToken()
		if s != "" {
			t.Errorf("Infinite Token should not be allowed for non-machine templates\n")
		}

		s = rd.GenerateProfileToken("foo", 30)
		if s != "UnknownMachineTokenNotAllowed" {
			t.Errorf("GenerateProfileToken should not generate a valid token for non-machines.\n")
		}
	})
	rt.Do(func(d Stores) {
		// Tests with machine and bootenv (has bad BootParams)
		rd := newRenderData(rt, machine, badBootEnv)
		_, e := rd.Param("bogus")
		if e == nil {
			t.Errorf("Param should return an error when machine is not defined in RenderData\n")
		} else if e.Error() != "No such machine parameter bogus" {
			t.Errorf("Param should return an error: No such machine parameter bogus, but returned: %s\n", e.Error())
		}
		_, e = rd.ParamExpand("bogus")
		if e == nil {
			t.Errorf("ParamExpand should return an error when machine is not defined in RenderData\n")
		} else if e.Error() != "No such machine parameter bogus" {
			t.Errorf("ParamExpand should return an error: No such machine parameter bogus, but returned: %s\n", e.Error())
		}
		_, e = rd.ParamExpand("fooBadExpand")
		if e == nil {
			t.Errorf("ParamExpand should return an error when bad data in parameter\n")
		} else if e.Error() != "Error compiling parameter fooBadExpand: template: machine:1: unclosed action" {
			t.Errorf("ParamExpand should return an error: Error compiling parameter fooBadExpand: template: machine:1: unclosed action, but returned: %s\n", e.Error())
		}
		_, e = rd.ParamExpand("fooBadExpand2")
		if e == nil {
			t.Errorf("ParamExpand should return an error when bad data in parameter\n")
		} else if e.Error() != "Error rendering parameter fooBadExpand2: template: machine:1:5: executing \"machine\" at <.PrionerURL>: can't evaluate field PrionerURL in type *backend.RenderData" {
			t.Errorf("ParamExpand should return an error: Error rendering parameter fooBadExpand2: template: machine:1:5: executing \"machine\" at <.PrionerURL>: can't evaluate field PrionerURL in type *backend.RenderData, but returned: %s\n", e.Error())
		}
		ok := rd.ParamExists("bogus")
		if ok {
			t.Errorf("ParamExists should return false when machine is not defined in RenderData\n")
		}

		// Test machine parameter
		p, e := rd.Param("foo")
		if e != nil {
			t.Errorf("Param foo should NOT return an error: %v\n", e)
		}
		s, ok := p.(string)
		if !ok {
			t.Errorf("Parameter foo should have been a string\n")
		} else {
			if s != "bar" {
				t.Errorf("Parameter foo should have been bar: %s\n", s)
			}
		}
		p, e = rd.ParamExpand("foo")
		if e != nil {
			t.Errorf("ParamExpand foo should NOT return an error: %v\n", e)
		}
		s, ok = p.(string)
		if !ok {
			t.Errorf("ParameterExpand foo should have been a string\n")
		} else {
			if s != "bar" {
				t.Errorf("ParameterExpand foo should have been bar: %s\n", s)
			}
		}
		p, e = rd.ParamExpand("fooExpand")
		if e != nil {
			t.Errorf("ParamExpand fooExpand should NOT return an error: %v\n", e)
		}
		s, ok = p.(string)
		if !ok {
			t.Errorf("ParamExpand fooExpand should have been a string\n")
		} else {
			if s != "barhttp://127.0.0.1:8091" {
				t.Errorf("ParamExpand foo should have been bar: %s\n", s)
			}
		}
		ok = rd.ParamExists("foo")
		if !ok {
			t.Errorf("ParamExists foo should return true when machine has foo defined in RenderData\n")
		}

		// Test global parameter
		p, e = rd.Param("test")
		if e != nil {
			t.Errorf("Param test should NOT return an error: %v\n", e)
		}
		s, ok = p.(string)
		if !ok {
			t.Errorf("Parameter test should have been a string\n")
		} else {
			if s != "foreal" {
				t.Errorf("Parameter test should have been foreal: %s\n", s)
			}
		}
		ok = rd.ParamExists("test")
		if !ok {
			t.Errorf("ParamExists test should return true when machine has foo defined in RenderData\n")
		}
		// Test a parameter with a default value embedded in the schema
		p, e = rd.Param("withDefault")
		if e != nil {
			t.Errorf("Param withDefault should NOT return an error: %v", e)
		}
		s, ok = p.(string)
		if !ok {
			t.Errorf("Parameter test with default should have been a string")
		} else if s != "default" {
			t.Errorf("Parameter test with default should have been `default`m not `%v`", s)
		}
	})
	rt.Do(func(d Stores) {
		// Test a machine profile parameter
		machine.Profiles = []string{"test"}
		saved, err := rt.Save(machine)
		if !saved {
			t.Errorf("Failed to save test machine with new profile list: %v", err)
		}
	})
	rt.Do(func(d Stores) {
		rd := newRenderData(rt, machine, badBootEnv)
		p, e := rd.Param("test")
		if e != nil {
			t.Errorf("Param test should NOT return an error: %v\n", e)
		}
		s, ok := p.(string)
		if !ok {
			t.Errorf("Parameter test should have been a string\n")
		} else {
			if s != "fred" {
				t.Errorf("Parameter test should have been fred: %s\n", s)
			}
		}
		ok = rd.ParamExists("test")
		if !ok {
			t.Errorf("ParamExists test should return true when machine profile has test defined in RenderData\n")
		}

		machineSecret := machine.Secret
		grantorSecret, _ := dt.Pref("systemGrantorSecret")

		s = rd.GenerateToken()
		claim, e := dt.GetToken(s)
		if e != nil {
			t.Errorf("GetToken should return a good claim. %v\n", e)
		}
		if claim.match(claimrt, models.MakeRole("", "machines", "create", "anything")) {
			t.Errorf("Known token should NOT match: machines/create/*\n")
		}
		if claim.match(claimrt, models.MakeRole("", "machines", "get", "anything")) {
			t.Errorf("Known token should NOT match: machines/get/*\n")
		}
		if claim.match(claimrt, models.MakeRole("", "machines", "update", "anything")) {
			t.Errorf("Known token should NOT match: machines/update/*\n")
		}
		if !claim.match(claimrt, models.MakeRole("", "machines", "get", machine.Key())) {
			t.Errorf("Known token should match: machines/get/%s\n", machine.Key())
		}
		if !claim.match(claimrt, models.MakeRole("", "machines", "update", machine.Key())) {
			t.Errorf("Known token should match: machines/update/%s\n", machine.Key())
		}
		if claim.ExpiresAt-claim.IssuedAt != 3600 {
			t.Errorf("Known token timeout should be 3600, but was %v\n", claim.ExpiresAt-claim.IssuedAt)
		}
		if !claim.ValidateSecrets(grantorSecret, "", machineSecret) {
			t.Errorf("Secrets validate to validate correctly: %s %s %s %s",
				grantorSecret, claim.GrantorClaims.GrantorSecret,
				machineSecret, claim.GrantorClaims.MachineSecret)
		}
		if !claim.ValidateSecrets(grantorSecret, "empty", machineSecret) {
			t.Errorf("Secrets validate to validate correctly: %s %s %s %s",
				grantorSecret, claim.GrantorClaims.GrantorSecret,
				machineSecret, claim.GrantorClaims.MachineSecret)
		}
		if claim.ValidateSecrets(grantorSecret+"1", "", machineSecret) {
			t.Errorf("Secrets validate should not validate correctly: %s %s %s %s",
				grantorSecret+"1", claim.GrantorClaims.GrantorSecret,
				machineSecret, claim.GrantorClaims.MachineSecret)
		}
		if claim.ValidateSecrets(grantorSecret, "", machineSecret+"1") {
			t.Errorf("Secrets validate should not validate correctly: %s %s %s %s",
				grantorSecret, claim.GrantorClaims.GrantorSecret,
				machineSecret+"1", claim.GrantorClaims.MachineSecret)
		}
		if claim.ValidateSecrets(grantorSecret+"1", "", machineSecret+"1") {
			t.Errorf("Secrets validate should not validate correctly: %s %s %s %s",
				grantorSecret+"1", claim.GrantorClaims.GrantorSecret,
				machineSecret+"1", claim.GrantorClaims.MachineSecret)
		}
		e = dt.SetPrefs(rt, map[string]string{"knownTokenTimeout": "50"})
		if e != nil {
			t.Errorf("SetPrefs should not return an error: %v\n", e)
		}
		s = rd.GenerateToken()
		claim, e = dt.GetToken(s)
		if e != nil {
			t.Errorf("GetToken should return a good claim. %v\n", e)
		}
		if claim.match(claimrt, models.MakeRole("", "machines", "create", "anything")) {
			t.Errorf("Known token should NOT match: machines/create/*\n")
		}
		if claim.match(claimrt, models.MakeRole("", "machines", "get", "anything")) {
			t.Errorf("Known token should NOT match: machines/get/*\n")
		}
		if claim.match(claimrt, models.MakeRole("", "machines", "update", "anything")) {
			t.Errorf("Known token should NOT match: machines/update/*\n")
		}
		if !claim.match(claimrt, models.MakeRole("", "machines", "get", machine.Key())) {
			t.Errorf("Known token should match: machines/get/%s\n", machine.Key())
		}
		if !claim.match(claimrt, models.MakeRole("", "machines", "update", machine.Key())) {
			t.Errorf("Known token should match: machines/update/%s\n", machine.Key())
		}
		if claim.ExpiresAt-claim.IssuedAt != 50 {
			t.Errorf("Known token timeout should be 50, but was %v\n", claim.ExpiresAt-claim.IssuedAt)
		}
		if !claim.ValidateSecrets(grantorSecret, "", machineSecret) {
			t.Errorf("Secrets validate to validate correctly: %s %s %s %s",
				grantorSecret, claim.GrantorClaims.GrantorSecret,
				machineSecret, claim.GrantorClaims.MachineSecret)
		}
		if !claim.ValidateSecrets(grantorSecret, "empty", machineSecret) {
			t.Errorf("Secrets validate to validate correctly: %s %s %s %s",
				grantorSecret, claim.GrantorClaims.GrantorSecret,
				machineSecret, claim.GrantorClaims.MachineSecret)
		}
		if claim.ValidateSecrets(grantorSecret+"1", "", machineSecret) {
			t.Errorf("Secrets validate should not validate correctly: %s %s %s %s",
				grantorSecret+"1", claim.GrantorClaims.GrantorSecret,
				machineSecret, claim.GrantorClaims.MachineSecret)
		}
		if claim.ValidateSecrets(grantorSecret, "", machineSecret+"1") {
			t.Errorf("Secrets validate should not validate correctly: %s %s %s %s",
				grantorSecret, claim.GrantorClaims.GrantorSecret,
				machineSecret+"1", claim.GrantorClaims.MachineSecret)
		}
		if claim.ValidateSecrets(grantorSecret+"1", "", machineSecret+"1") {
			t.Errorf("Secrets validate should not validate correctly: %s %s %s %s",
				grantorSecret+"1", claim.GrantorClaims.GrantorSecret,
				machineSecret+"1", claim.GrantorClaims.MachineSecret)
		}

		s = rd.GenerateInfiniteToken()
		claim, e = dt.GetToken(s)
		if e != nil {
			t.Errorf("GetToken should return a good claim. %v\n", e)
		}
		if claim.match(claimrt, models.MakeRole("", "machines", "create", "anything")) {
			t.Errorf("Known token should NOT match: machines/create/*\n")
		}
		if claim.match(claimrt, models.MakeRole("", "machines", "get", "anything")) {
			t.Errorf("Known token should NOT match: machines/get/*\n")
		}
		if claim.match(claimrt, models.MakeRole("", "machines", "update", "anything")) {
			t.Errorf("Known token should NOT match: machines/update/*\n")
		}
		if !claim.match(claimrt, models.MakeRole("", "machines", "get", machine.Key())) {
			t.Errorf("Known token should match: machines/get/%s\n", machine.Key())
		}
		if !claim.match(claimrt, models.MakeRole("", "machines", "update", machine.Key())) {
			t.Errorf("Known token should match: machines/update/%s\n", machine.Key())
		}
		if claim.ExpiresAt-claim.IssuedAt <= 100000 {
			t.Errorf("Known token timeout should > 100000, but was %v\n", claim.ExpiresAt-claim.IssuedAt)
		}
		if !claim.ValidateSecrets(grantorSecret, "", machineSecret) {
			t.Errorf("Secrets validate to validate correctly: %s %s %s %s",
				grantorSecret, claim.GrantorClaims.GrantorSecret,
				machineSecret, claim.GrantorClaims.MachineSecret)
		}
		if !claim.ValidateSecrets(grantorSecret, "empty", machineSecret) {
			t.Errorf("Secrets validate to validate correctly: %s %s %s %s",
				grantorSecret, claim.GrantorClaims.GrantorSecret,
				machineSecret, claim.GrantorClaims.MachineSecret)
		}
		if claim.ValidateSecrets(grantorSecret+"1", "", machineSecret) {
			t.Errorf("Secrets validate should not validate correctly: %s %s %s %s",
				grantorSecret+"1", claim.GrantorClaims.GrantorSecret,
				machineSecret, claim.GrantorClaims.MachineSecret)
		}
		if claim.ValidateSecrets(grantorSecret, "", machineSecret+"1") {
			t.Errorf("Secrets validate should not validate correctly: %s %s %s %s",
				grantorSecret, claim.GrantorClaims.GrantorSecret,
				machineSecret+"1", claim.GrantorClaims.MachineSecret)
		}
		if claim.ValidateSecrets(grantorSecret+"1", "", machineSecret+"1") {
			t.Errorf("Secrets validate should not validate correctly: %s %s %s %s",
				grantorSecret+"1", claim.GrantorClaims.GrantorSecret,
				machineSecret+"1", claim.GrantorClaims.MachineSecret)
		}

		s = rd.GenerateProfileToken("noprofile", 30)
		if s != "InvalidTokenNotAllowedNotOnMachine" {
			t.Errorf("GenerateProfileToken should return a bad token for profiles not on the machine: actual: %s", s)
		}

		s = rd.GenerateProfileToken("test", 30)
		claim, e = dt.GetToken(s)
		if e != nil {
			t.Errorf("GenerateProfileToken should return a good claim. %v, %s\n", e, s)
		}
		if !claim.match(claimrt, models.MakeRole("", "profiles", "update", "test")) {
			t.Errorf("ProfileToken should match update/test")
		}
		if !claim.match(claimrt, models.MakeRole("", "profiles", "update", "test")) {
			t.Errorf("ProfileToken should match update/test")
		}
		if claim.ExpiresAt-claim.IssuedAt != 30 {
			t.Errorf("ProfileToken timeout should = 30, but was %v\n", claim.ExpiresAt-claim.IssuedAt)
		}
		if !claim.ValidateSecrets(grantorSecret, "", machineSecret) {
			t.Errorf("Secrets validate to validate correctly: %s %s %s %s",
				grantorSecret, claim.GrantorClaims.GrantorSecret,
				machineSecret, claim.GrantorClaims.MachineSecret)
		}
		if !claim.ValidateSecrets(grantorSecret, "empty", machineSecret) {
			t.Errorf("Secrets validate to validate correctly: %s %s %s %s",
				grantorSecret, claim.GrantorClaims.GrantorSecret,
				machineSecret, claim.GrantorClaims.MachineSecret)
		}
		if claim.ValidateSecrets(grantorSecret+"1", "", machineSecret) {
			t.Errorf("Secrets validate should not validate correctly: %s %s %s %s",
				grantorSecret+"1", claim.GrantorClaims.GrantorSecret,
				machineSecret, claim.GrantorClaims.MachineSecret)
		}
		if claim.ValidateSecrets(grantorSecret, "", machineSecret+"1") {
			t.Errorf("Secrets validate should not validate correctly: %s %s %s %s",
				grantorSecret, claim.GrantorClaims.GrantorSecret,
				machineSecret+"1", claim.GrantorClaims.MachineSecret)
		}
		if claim.ValidateSecrets(grantorSecret+"1", "", machineSecret+"1") {
			t.Errorf("Secrets validate should not validate correctly: %s %s %s %s",
				grantorSecret+"1", claim.GrantorClaims.GrantorSecret,
				machineSecret+"1", claim.GrantorClaims.MachineSecret)
		}

		s = rd.GenerateProfileToken("test", 0)
		claim, e = dt.GetToken(s)
		if e != nil {
			t.Errorf("GenerateProfileToken should return a good claim. %v, %s\n", e, s)
		}
		if !claim.match(claimrt, models.MakeRole("", "profiles", "update", "test")) {
			t.Errorf("ProfileToken should match update/test")
		}
		if !claim.match(claimrt, models.MakeRole("", "profiles", "update", "test")) {
			t.Errorf("ProfileToken should match update/test")
		}
		if claim.ExpiresAt-claim.IssuedAt < 100000 {
			t.Errorf("ProfileToken timeout should be > 10000, but was %v\n", claim.ExpiresAt-claim.IssuedAt)
		}
		if !claim.ValidateSecrets(grantorSecret, "", machineSecret) {
			t.Errorf("Secrets validate to validate correctly: %s %s %s %s",
				grantorSecret, claim.GrantorClaims.GrantorSecret,
				machineSecret, claim.GrantorClaims.MachineSecret)
		}
		if !claim.ValidateSecrets(grantorSecret, "empty", machineSecret) {
			t.Errorf("Secrets validate to validate correctly: %s %s %s %s",
				grantorSecret, claim.GrantorClaims.GrantorSecret,
				machineSecret, claim.GrantorClaims.MachineSecret)
		}
		if claim.ValidateSecrets(grantorSecret+"1", "", machineSecret) {
			t.Errorf("Secrets validate should not validate correctly: %s %s %s %s",
				grantorSecret+"1", claim.GrantorClaims.GrantorSecret,
				machineSecret, claim.GrantorClaims.MachineSecret)
		}
		if claim.ValidateSecrets(grantorSecret, "", machineSecret+"1") {
			t.Errorf("Secrets validate should not validate correctly: %s %s %s %s",
				grantorSecret, claim.GrantorClaims.GrantorSecret,
				machineSecret+"1", claim.GrantorClaims.MachineSecret)
		}
		if claim.ValidateSecrets(grantorSecret+"1", "", machineSecret+"1") {
			t.Errorf("Secrets validate should not validate correctly: %s %s %s %s",
				grantorSecret+"1", claim.GrantorClaims.GrantorSecret,
				machineSecret+"1", claim.GrantorClaims.MachineSecret)
		}

	})

}
