package api

import (
	"log"
	"testing"

	"github.com/digitalrebar/provision/models"
)

func TestContentCrud(t *testing.T) {
	summary := `
- Counts:
    bootenvs: 0
    jobs: 0
    leases: 0
    machines: 0
    params: 0
    plugins: 0
    preferences: 13
    profiles: 1
    reservations: 0
    roles: 0
    stages: 0
    subnets: 0
    tasks: 0
    templates: 0
    tenants: 0
    users: 1
    workflows: 0
  Warnings: []
  meta:
    Description: Writable backing store
    Meta: {}
    Name: BackingStore
    Overwritable: false
    Source: ""
    Type: writable
    Version: 0.0.0
    Writable: true
- Counts:
    templates: 1
  Warnings: []
  meta:
    Description: Local Override Store
    Meta: {}
    Name: LocalStore
    Overwritable: true
    Source: ""
    Type: local
    Version: 0.0.0
    Writable: false
- Counts:
    templates: 1
  Warnings: []
  meta:
    Description: Initial Default Content
    Meta: {}
    Name: DefaultStore
    Overwritable: true
    Source: ""
    Type: default
    Version: 0.0.0
    Writable: false
- Counts:
    params: 5
  Warnings: []
  meta:
    Description: Test Plugin for DRP
    Meta: {}
    Name: incrementer
    Overwritable: false
    Prerequisites: ""
    RequiredFeatures: ""
    Source: FromPluginProvider
    Type: plugin
    Version: v3.10.1000-pre-alpha-NotSet
    Writable: false
- Counts:
    bootenvs: 2
    roles: 1
    params: 1
    stages: 2
  Warnings: []
  meta:
    Description: Default objects that must be present
    Meta: {}
    Name: BasicStore
    Overwritable: true
    Source: ""
    Type: basic
    Version: 3.12.0
    Writable: false
`
	cs := []models.ContentSummary{}
	if err := DecodeYaml([]byte(summary), &cs); err != nil {
		log.Panicf("Unable to decode reference content summary: %v", err)
	}
	backingStore := `
meta:
  Description: Writable backing store
  Meta: {}
  Name: BackingStore
  Overwritable: false
  Source: ""
  Type: writable
  Version: 0.0.0
  Writable: true
sections:
  bootenvs: {}
  jobs: {}
  leases: {}
  machines: {}
  params: {}
  plugins: {}
  preferences:
    baseTokenSecret:
      Meta: {}
      Name: baseTokenSecret
      Val: elided
    debugBootEnv:
      Meta: {}
      Name: debugBootEnv
      Val: warn
    debugDhcp:
      Meta: {}
      Name: debugDhcp
      Val: warn
    debugFrontend:
      Meta: {}
      Name: debugFrontend
      Val: warn
    debugPlugins:
      Meta: {}
      Name: debugPlugins
      Val: warn
    debugRenderer:
      Meta: {}
      Name: debugRenderer
      Val: warn
    defaultBootEnv:
      Meta: {}
      Name: defaultBootEnv
      Val: local
    defaultStage:
      Meta: {}
      Name: defaultStage
      Val: none
    knownTokenTimeout:
      Meta: {}
      Name: knownTokenTimeout
      Val: "3600"
    logLevel:
      Meta: {}
      Name: logLevel
      Val: warn
    systemGrantorSecret:
      Meta: {}
      Name: systemGrantorSecret
      Val: elided
    unknownBootEnv:
      Meta: {}
      Name: unknownBootEnv
      Val: ignore
    unknownTokenTimeout:
      Meta: {}
      Name: unknownTokenTimeout
      Val: "600"
  profiles:
    global:
      Available: false
      Bundle: BackingStore
      Description: Global profile attached automatically to all machines.
      Documentation: ""
      Endpoint: ""
      Errors: []
      Meta:
        color: blue
        icon: world
        title: Digital Rebar Provision
      Name: global
      Params: {}
      Partial: false
      ReadOnly: false
      Validated: false
  reservations: {}
  roles: {}
  stages: {}
  subnets: {}
  tasks: {}
  templates: {}
  tenants: {}
  users:
    rocketskates:
      Available: false
      Bundle: BackingStore
      Description: ""
      Endpoint: ""
      Errors: []
      Meta: {}
      Name: rocketskates
      PasswordHash: elided
      ReadOnly: false
      Roles:
      - superuser
      Secret: elided
      Validated: false
  workflows: {}
`
	bs := &models.Content{}
	if err := DecodeYaml([]byte(backingStore), bs); err != nil {
		log.Panicf("Unable to unmarshal backingStore: %v", err)
	}
	tests := []crudTest{
		{
			name:      "List all content",
			expectRes: cs,
			expectErr: nil,
			op: func() (interface{}, error) {
				return session.GetContentSummary()
			},
		},
		{
			name:      "Get BackingStore",
			expectRes: bs,
			expectErr: nil,
			op: func() (interface{}, error) {
				res, err := session.GetContentItem("BackingStore")
				if err != nil {
					return res, err
				}
				res.Sections["users"]["rocketskates"].(map[string]interface{})["PasswordHash"] = "elided"
				res.Sections["users"]["rocketskates"].(map[string]interface{})["Secret"] = "elided"
				res.Sections["preferences"]["systemGrantorSecret"].(map[string]interface{})["Val"] = "elided"
				res.Sections["preferences"]["baseTokenSecret"].(map[string]interface{})["Val"] = "elided"
				return res, err
			},
		},
		{
			name:      "Get BarkingStore (that does not exist)",
			expectRes: nil,
			expectErr: &models.Error{
				Model:    "contents",
				Key:      "BarkingStore",
				Type:     "GET",
				Messages: []string{"No such content store"},
				Code:     404,
			},
			op: func() (interface{}, error) {
				return session.GetContentItem("BarkingStore")
			},
		},
		{
			name:      "Delete BarkingStore (that does not exist)",
			expectRes: nil,
			expectErr: &models.Error{
				Model:    "contents",
				Key:      "BarkingStore",
				Type:     "DELETE",
				Messages: []string{"No such content store"},
				Code:     404,
			},
			op: func() (interface{}, error) {
				return nil, session.DeleteContent("BarkingStore")
			},
		},
		{
			name:      "Create Bad BarkingStore (no name)",
			expectRes: nil,
			expectErr: &models.Error{
				Model:    "contents",
				Key:      "",
				Type:     "STORE_ERROR",
				Messages: []string{"Content Store must have a name", "Store at content- has no Name metadata"},
				Code:     422,
			},
			op: func() (interface{}, error) {
				barking := &models.Content{}
				barking.Fill()
				return session.CreateContent(barking)
			},
		},
		{
			name: "Create BarkingStore",
			expectRes: mustDecode(&models.ContentSummary{}, `
Counts: {}
Warnings: []
meta:
  Description: ""
  Meta: {}
  Name: BarkingStore
  Overwritable: false
  Source: ""
  Type: dynamic
  Version: ""
  Writable: false
`),
			expectErr: nil,
			op: func() (interface{}, error) {
				barking := &models.Content{}
				barking.Fill()
				barking.Meta.Name = "BarkingStore"
				return session.CreateContent(barking)
			},
		},
		{
			name:      "Create Duplicate BarkingStore",
			expectRes: nil,
			expectErr: &models.Error{
				Model:    "contents",
				Key:      "BarkingStore",
				Type:     "POST",
				Messages: []string{"Content BarkingStore already exists"},
				Code:     409,
			},
			op: func() (interface{}, error) {
				barking := &models.Content{}
				barking.Fill()
				barking.Meta.Name = "BarkingStore"
				return session.CreateContent(barking)
			},
		},
		{
			name:      "Update BarkingStore (that would break layers)",
			expectRes: nil,
			expectErr: &models.Error{
				Model: "contents",
				Key:   "BarkingStore",
				Type:  "PUT",
				Messages: []string{
					"New layer violates key restrictions: keysCannotBeOverridden: global is already in layer 0\n\tkeysCannotOverride: global would be overridden by layer 0"},
				Code: 500,
			},
			op: func() (interface{}, error) {
				barking := &models.Content{}
				barking.Fill()
				barking.Meta.Name = "BarkingStore"
				env, err := session.GetModel("profiles", "global")
				if err != nil {
					return nil, err
				}
				barking.Sections["profiles"] = map[string]interface{}{env.Key(): env}
				return session.ReplaceContent(barking)
			},
		},
		{
			name: "Update BarkingStore",
			expectRes: mustDecode(&models.ContentSummary{}, `
Counts:
  bootenvs: 1
Warnings: []
meta:
  Description: ""
  Meta: {}
  Name: BarkingStore
  Overwritable: false
  Source: ""
  Type: dynamic
  Version: ""
  Writable: false
`),
			expectErr: nil,
			op: func() (interface{}, error) {
				barking := &models.Content{}
				barking.Fill()
				barking.Meta.Name = "BarkingStore"
				env, err := session.GetModel("bootenvs", "ignore")
				if err != nil {
					return nil, err
				}
				env.(*models.BootEnv).Name = "ignoble"
				barking.Sections["bootenvs"] = map[string]interface{}{env.Key(): env}
				return session.ReplaceContent(barking)
			},
		},
		{
			name: "Make sure we can get the ignoble boot env",
			expectRes: mustDecode(&models.BootEnv{}, `
Available: true
Endpoint: ""
Bundle: BarkingStore
Description: The boot environment you should use to have unknown machines boot off
  their local hard drive
Meta:
  color: green
  feature-flags: change-stage-v2
  icon: circle thin
  title: Digital Rebar Provision
Name: ignoble
OS:
  Name: ignore
OnlyUnknown: true
ReadOnly: true
Templates:
- Contents: |
    DEFAULT local
    PROMPT 0
    TIMEOUT 10
    LABEL local
    {{.Param "pxelinux-local-boot"}}
  Name: pxelinux
  Meta: {}
  Path: pxelinux.cfg/default
- Contents: |
    #!ipxe
    chain {{.ProvisionerURL}}/${netX/mac}.ipxe && exit || goto chainip
    :chainip
    chain tftp://{{.ProvisionerAddress}}/${netX/ip}.ipxe || exit
  Name: ipxe
  Meta: {}
  Path: default.ipxe
- Contents: |
    set _kernel=linux
    set _module=initrd
    $_kernel
    if test $? != 18; then
        set _kernel=linuxefi
        set _module=initrdefi
    fi
    function kernel { $_kernel "$@"; }
    function module { $_module "$@"; }
    if test -s (tftp)/grub/${net_default_mac}.cfg; then
        echo "Booting via MAC"
        source (tftp)/grub/${net_default_mac}.cfg
        boot
    elif test -s (tftp)/grub/${net_default_ip}.cfg; then
        echo "Booting via IP"
        source (tftp)/grub/${net_default_ip}.cfg
        boot
    elif test $grub_platform == pc; then
        chainloader (hd0)
    else
        bpx=/efi/boot
        root='' prefix=''
        search --file --set=root $bpx/bootx64.efi || search --file --set=root $bpx/bootaa64.efi
        if test x$root == x; then
            echo "No EFI boot partiton found."
            echo "Rebooting in 120 seconds"
            sleep 120
            reboot
        fi
        if test -f ($root)/efi/microsoft/boot/bootmgfw.efi; then
            echo "Microsoft Windows found, chainloading into it"
            chainloader ($root)/efi/microsoft/boot/bootmgfw.efi
        fi
        for f in ($root)/efi/*; do
            if test -f $f/grub.cfg; then
                prefix=$f
                break
            fi
        done
        if test x$prefix == x; then
            echo "Unable to find grub.cfg"
            echo "Rebooting in 120 seconds"
            sleep 120
            reboot
        fi
        configfile $prefix/grub.cfg
    fi
  ID: ""
  Meta: {}
  Name: grub
  Path: grub/grub.cfg
Validated: true
`),
			expectErr: nil,
			op: func() (interface{}, error) {
				return session.GetModel("bootenvs", "ignoble")
			},
		},
		{
			name:      "Delete BarkingStore",
			expectRes: nil,
			expectErr: nil,
			op: func() (interface{}, error) {
				return nil, session.DeleteContent("BarkingStore")
			},
		},
		{
			name:      "Make sure the ignoble boot env is gone",
			expectRes: nil,
			expectErr: &models.Error{
				Model:    "bootenvs",
				Key:      "ignoble",
				Type:     "GET",
				Messages: []string{"Not Found"},
				Code:     404,
			},
			op: func() (interface{}, error) {
				return session.GetModel("bootenvs", "ignoble")
			},
		},
	}

	for _, test := range tests {
		test.run(t)
	}
}
