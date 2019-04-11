// Package server DigitalRebar Provision Server
//
// An RestFUL API-driven Provisioner and DHCP server
//
// Terms Of Service:
//
// There are no TOS at this moment, use at your own risk we take no responsibility
//
//     Schemes: https
//     BasePath: /api/v3
//     Version: 0.1.0
//     License: APL https://raw.githubusercontent.com/digitalrebar/digitalrebar/master/LICENSE.md
//     Contact: Greg Althaus<greg@rackn.com> http://rackn.com
//
//     Security:
//       - basicAuth: []
//       - Bearer: []
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
// swagger:meta
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	"github.com/digitalrebar/logger"
	"github.com/digitalrebar/provision"
	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/frontend"
	"github.com/digitalrebar/provision/midlayer"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/provision/utils"
	"github.com/digitalrebar/store"
)

// EmbeddedAssetsExtractFunc is a function pointer that can set at initialization
// time to enable the exploding of data.  This is used to avoid having to have
// a fully generated binary for testing purposes.
var EmbeddedAssetsExtractFunc func(string, string) error

// ProgOpts defines the DRP server command line options.
type ProgOpts struct {
	VersionFlag         bool   `long:"version" description:"Print Version and exit"`
	DisableTftpServer   bool   `long:"disable-tftp" description:"Disable TFTP server" env:"RS_DISABLE_TFTP_SERVER"`
	DisableProvisioner  bool   `long:"disable-provisioner" description:"Disable provisioner" env:"RS_DISABLE_PROVISIONER"`
	DisableDHCP         bool   `long:"disable-dhcp" description:"Disable DHCP server" env:"RS_DISABLE_DHCP"`
	DisableBINL         bool   `long:"disable-pxe" description:"Disable PXE/BINL server" env:"RS_DISABLE_BINL"`
	MetricsPort         int    `long:"metrics-port" description:"Port the metrics HTTP server should listen on" default:"8080" env:"RS_METRICS_PORT"`
	StaticPort          int    `long:"static-port" description:"Port the static HTTP file server should listen on" default:"8091" env:"RS_STATIC_PORT"`
	TftpPort            int    `long:"tftp-port" description:"Port for the TFTP server to listen on" default:"69" env:"RS_TFTP_PORT"`
	ApiPort             int    `long:"api-port" description:"Port for the API server to listen on" default:"8092" env:"RS_API_PORT"`
	DhcpPort            int    `long:"dhcp-port" description:"Port for the DHCP server to listen on" default:"67" env:"RS_DHCP_PORT"`
	BinlPort            int    `long:"binl-port" description:"Port for the PXE/BINL server to listen on" default:"4011" env:"RS_BINL_PORT"`
	UnknownTokenTimeout int    `long:"unknown-token-timeout" description:"The default timeout in seconds for the machine create authorization token" default:"600" env:"RS_UNKNOWN_TOKEN_TIMEOUT"`
	KnownTokenTimeout   int    `long:"known-token-timeout" description:"The default timeout in seconds for the machine update authorization token" default:"3600" env:"RS_KNOWN_TOKEN_TIMEOUT"`
	OurAddress          string `long:"static-ip" description:"IP address to advertise for the static HTTP file server" default:"" env:"RS_STATIC_IP"`
	ForceStatic         bool   `long:"force-static" description:"Force the system to always use the static IP." env:"RS_FORCE_STATIC"`

	BackEndType    string `long:"backend" description:"Storage to use for persistent data. Can be either 'consul', 'directory', or a store URI" default:"directory" env:"RS_BACKEND_TYPE"`
	SecretsType    string `long:"secrets" description:"Storage to use for persistent data. Can be either 'consul', 'directory', or a store URI.  Will default to being the same as 'backend'" default:"" env:"RS_SECRETS_TYPE"`
	LocalContent   string `long:"local-content" description:"Storage to use for local overrides." default:"directory:///etc/dr-provision?codec=yaml" env:"RS_LOCAL_CONTENT"`
	DefaultContent string `long:"default-content" description:"Store URL for local content" default:"file:///usr/share/dr-provision/default.yaml?codec=yaml" env:"RS_DEFAULT_CONTENT"`

	BaseRoot        string `long:"base-root" description:"Base directory for other root dirs." default:"/var/lib/dr-provision" env:"RS_BASE_ROOT"`
	DataRoot        string `long:"data-root" description:"Location we should store runtime information in" default:"digitalrebar" env:"RS_DATA_ROOT"`
	SecretsRoot     string `long:"secrets-root" description:"Location we should store encrypted parameter private keys in" default:"secrets" env:"RS_SECRETS_ROOT"`
	PluginRoot      string `long:"plugin-root" description:"Directory for plugins" default:"plugins" env:"RS_PLUGIN_ROOT"`
	PluginCommRoot  string `long:"plugin-comm-root" description:"Directory for the communications for plugins" default:"/var/run" env:"RS_PLUGIN_COMM_ROOT"`
	LogRoot         string `long:"log-root" description:"Directory for job logs" default:"job-logs" env:"RS_LOG_ROOT"`
	SaasContentRoot string `long:"saas-content-root" description:"Directory for additional content" default:"saas-content" env:"RS_SAAS_CONTENT_ROOT"`
	FileRoot        string `long:"file-root" description:"Root of filesystem we should manage" default:"tftpboot" env:"RS_FILE_ROOT"`
	ReplaceRoot     string `long:"replace-root" description:"Root of filesystem we should use to replace embedded assets" default:"replace" env:"RS_REPLACE_ROOT"`

	LocalUI        string `long:"local-ui" description:"Root of Local UI Pages" default:"ux" env:"RS_LOCAL_UI"`
	UIUrl          string `long:"ui-url" description:"URL to redirect to UI" default:"https://portal.rackn.io" env:"RS_UI_URL"`
	DhcpInterfaces string `long:"dhcp-ifs" description:"Comma-separated list of interfaces to listen for DHCP packets" default:"" env:"RS_DHCP_INTERFACES"`
	DefaultStage   string `long:"default-stage" description:"The default stage for the nodes" default:"none" env:"RS_DEFAULT_STAGE"`
	DefaultBootEnv string `long:"default-boot-env" description:"The default bootenv for the nodes" default:"local" env:"RS_DEFAULT_BOOTENV"`
	UnknownBootEnv string `long:"unknown-boot-env" description:"The unknown bootenv for the system.  Should be \"ignore\" or \"discovery\"" default:"ignore" env:"RS_UNKNOWN_BOOTENV"`

	DebugBootEnv  string `long:"debug-bootenv" description:"Debug level for the BootEnv System" default:"warn" env:"RS_DEBUG_BOOTENV"`
	DebugDhcp     string `long:"debug-dhcp" description:"Debug level for the DHCP Server" default:"warn" env:"RS_DEBUG_DHCP"`
	DebugRenderer string `long:"debug-renderer" description:"Debug level for the Template Renderer" default:"warn" env:"RS_DEBUG_RENDERER"`
	DebugFrontend string `long:"debug-frontend" description:"Debug level for the Frontend" default:"warn" env:"RS_DEBUG_FRONTEND"`
	DebugPlugins  string `long:"debug-plugins" description:"Debug level for the Plug-in layer" default:"warn" env:"RS_DEBUG_PLUGINS"`
	TlsKeyFile    string `long:"tls-key" description:"The TLS Key File" default:"server.key" env:"RS_TLS_KEY_FILE"`
	TlsCertFile   string `long:"tls-cert" description:"The TLS Cert File" default:"server.crt" env:"RS_TLS_CERT_FILE"`
	UseOldCiphers bool   `long:"use-old-ciphers" description:"Use Original Less Secure Cipher List" env:"RS_USE_OLD_CIPHERS"`
	DrpId         string `long:"drp-id" description:"The id of this Digital Rebar Provision instance" default:"" env:"RS_DRP_ID"`
	HaId          string `long:"ha-id" description:"The id of this Digital Rebar Provision HA Cluster" default:"" env:"RS_HA_ID"`
	CurveOrBits   string `long:"cert-type" description:"Type of cert to generate. values are: P224, P256, P384, P521, RSA, or <number of RSA bits>" default:"P384" env:"RS_CURVE_OR_BITS"`

	BaseTokenSecret     string `long:"base-token-secret" description:"Auth Token secret to allow revocation of all tokens" default:"" env:"RS_BASE_TOKEN_SECRET"`
	SystemGrantorSecret string `long:"system-grantor-secret" description:"Auth Token secret to allow revocation of all Machine tokens" default:"" env:"RS_SYSTEM_GRANTOR_SECRET"`
	FakePinger          bool   `hidden:"true" long:"fake-pinger" env:"RS_FAKE_PINGER"`
	DefaultLogLevel     string `long:"log-level" description:"Level to log messages at" default:"warn" env:"RS_DEFAULT_LOG_LEVEL"`

	HaEnabled   bool   `long:"ha-enabled" description:"Enable HA" env:"RS_HA_ENABLED"`
	HaAddress   string `long:"ha-address" description:"IP address to advertise as our HA address" default:"" env:"RS_HA_ADDRESS"`
	HaInterface string `long:"ha-interface" description:"Interface to put the VIP on for HA" default:"" env:"RS_HA_INTERFACE"`

	PromGwUrl      string `long:"prometheus-gateway-url" description:"URL to push metrics to" default:"" env:"RS_PROM_GW_URL"`
	PromInterval   int    `long:"prometheus-interval" description:"Duration in seconds to push metrics" default:"5" env:"RS_PROM_INTERVAL"`
	CleanupCorrupt bool   `long:"cleanup" description:"Clean up corrupted writable data.  Only use when directed." env:"RS_CLEANUP_CORRUPT"`
}

func mkdir(d string) error {
	return os.MkdirAll(d, 0755)
}

func processArgs(localLogger *log.Logger, cOpts *ProgOpts) error {
	localLogger.Printf("Processing arguments")
	var err error

	if cOpts.VersionFlag {
		return fmt.Errorf("Version: %s", provision.RSVersion)
	}
	localLogger.Printf("Version: %s\n", provision.RSVersion)

	// Make base root dir
	if err = mkdir(cOpts.BaseRoot); err != nil {
		return fmt.Errorf("Error creating required directory %s: %v", cOpts.BaseRoot, err)
	}

	// Make other dirs as needed - adjust the dirs as well.
	if strings.IndexRune(cOpts.FileRoot, filepath.Separator) != 0 {
		cOpts.FileRoot = filepath.Join(cOpts.BaseRoot, cOpts.FileRoot)
	}
	if cOpts.SecretsType == "" {
		cOpts.SecretsType = cOpts.BackEndType
	}
	if cOpts.SecretsType == "directory" && strings.IndexRune(cOpts.SecretsRoot, filepath.Separator) != 0 {
		cOpts.SecretsRoot = filepath.Join(cOpts.BaseRoot, cOpts.SecretsRoot)
	}
	if cOpts.SecretsType == "consul" && strings.IndexRune(cOpts.SecretsRoot, filepath.Separator) != 0 {
		cOpts.SecretsRoot = fmt.Sprintf("/%s", cOpts.SecretsRoot)
	}
	if strings.IndexRune(cOpts.PluginRoot, filepath.Separator) != 0 {
		cOpts.PluginRoot = filepath.Join(cOpts.BaseRoot, cOpts.PluginRoot)
	}
	if strings.IndexRune(cOpts.PluginCommRoot, filepath.Separator) != 0 {
		cOpts.PluginCommRoot = filepath.Join(cOpts.BaseRoot, cOpts.PluginCommRoot)
	}
	if len(cOpts.PluginCommRoot) > 70 {
		return fmt.Errorf("PluginCommRoot Must be less than 70 characters")
	}
	if cOpts.BackEndType == "directory" && strings.IndexRune(cOpts.DataRoot, filepath.Separator) != 0 {
		cOpts.DataRoot = filepath.Join(cOpts.BaseRoot, cOpts.DataRoot)
	}
	if cOpts.BackEndType == "consul" && strings.IndexRune(cOpts.DataRoot, filepath.Separator) != 0 {
		cOpts.DataRoot = fmt.Sprintf("/%s", cOpts.DataRoot)
	}
	if strings.IndexRune(cOpts.LogRoot, filepath.Separator) != 0 {
		cOpts.LogRoot = filepath.Join(cOpts.BaseRoot, cOpts.LogRoot)
	}
	if strings.IndexRune(cOpts.SaasContentRoot, filepath.Separator) != 0 {
		cOpts.SaasContentRoot = filepath.Join(cOpts.BaseRoot, cOpts.SaasContentRoot)
	}
	if strings.IndexRune(cOpts.ReplaceRoot, filepath.Separator) != 0 {
		cOpts.ReplaceRoot = filepath.Join(cOpts.BaseRoot, cOpts.ReplaceRoot)
	}
	if strings.IndexRune(cOpts.LocalUI, filepath.Separator) != 0 {
		cOpts.LocalUI = filepath.Join(cOpts.BaseRoot, cOpts.LocalUI)
	}
	if err = mkdir(path.Join(cOpts.FileRoot, "isos")); err != nil {
		return fmt.Errorf("Error creating required directory %s: %v", cOpts.FileRoot, err)
	}
	if err = mkdir(path.Join(cOpts.FileRoot, "files")); err != nil {
		return fmt.Errorf("Error creating required directory %s: %v", cOpts.FileRoot, err)
	}
	if err = mkdir(cOpts.ReplaceRoot); err != nil {
		return fmt.Errorf("Error creating required directory %s: %v", cOpts.ReplaceRoot, err)
	}
	if err = mkdir(cOpts.PluginRoot); err != nil {
		return fmt.Errorf("Error creating required directory %s: %v", cOpts.PluginRoot, err)
	}
	if err = mkdir(cOpts.PluginCommRoot); err != nil {
		return fmt.Errorf("Error creating required directory %s: %v", cOpts.PluginCommRoot, err)
	}
	if cOpts.BackEndType == "directory" {
		if err = mkdir(cOpts.DataRoot); err != nil {
			return fmt.Errorf("Error creating required directory %s: %v", cOpts.DataRoot, err)
		}
	}
	if err = mkdir(cOpts.LogRoot); err != nil {
		return fmt.Errorf("Error creating required directory %s: %v", cOpts.LogRoot, err)
	}
	if err = mkdir(cOpts.LocalUI); err != nil {
		return fmt.Errorf("Error creating required directory %s: %v", cOpts.LocalUI, err)
	}
	if err = mkdir(cOpts.SaasContentRoot); err != nil {
		return fmt.Errorf("Error creating required directory %s: %v", cOpts.SaasContentRoot, err)
	}
	if cOpts.SecretsType == "directory" {
		if err = mkdir(cOpts.SecretsRoot); err != nil {
			return fmt.Errorf("Error creating required directory %s: %v", cOpts.SecretsRoot, err)
		}
	}
	// Validate HA args - Assumes a local consul server running talking to the "cluster"
	if cOpts.HaEnabled {
		if cOpts.SecretsType != "consul" || cOpts.BackEndType != "consul" {
			return fmt.Errorf("Error: HA must be run on consul backends: %s, %s", cOpts.SecretsType, cOpts.BackEndType)
		}

		if cOpts.HaAddress == "" {
			return fmt.Errorf("Error: HA must specify a VIP that DRP will move around")
		}

		if cOpts.HaInterface == "" {
			return fmt.Errorf("Error: HA must specify an interface for the VIP that DRP will move around")
		}

		ip := net.ParseIP(cOpts.HaAddress)
		if ip == nil {
			return fmt.Errorf("Error: HA must be an IP address: %s", cOpts.HaAddress)
		}

		if cOpts.OurAddress != "" {
			oip := net.ParseIP(cOpts.OurAddress)
			if oip == nil {
				return fmt.Errorf("Error: OurAddress must be an IP address: %s", cOpts.OurAddress)
			}
			if !oip.Equal(ip) {
				return fmt.Errorf("Error: HA Address must match OurAddress. %s != %s", cOpts.HaAddress, cOpts.OurAddress)
			}
		} else {
			cOpts.OurAddress = cOpts.HaAddress
		}
	}

	if EmbeddedAssetsExtractFunc != nil {
		localLogger.Printf("Extracting Default Assets\n")
		if err := EmbeddedAssetsExtractFunc(cOpts.ReplaceRoot, cOpts.FileRoot); err != nil {
			return fmt.Errorf("Unable to extract assets: %v", err)
		}
	}
	return nil
}

func makeLogBuffer(localLogger *log.Logger, cOpts *ProgOpts) (*logger.Buffer, error) {
	logLevel, err := logger.ParseLevel(cOpts.DefaultLogLevel)
	if err != nil {
		localLogger.Printf("Invalid log level %s", cOpts.DefaultLogLevel)
		return nil, fmt.Errorf("Try one of `trace`,`debug`,`info`,`warn`,`error`,`fatal`,`panic`")
	}
	return logger.New(localLogger).SetDefaultLevel(logLevel), nil
}

func waitOnApi(cOpts *ProgOpts) {
	// Wait for Api to come up
	for count := 1; count <= 7; count++ {
		log.Printf("Waiting for API (%d) to come up...\n", count)
		timeout := time.Duration(count) * time.Second
		tr := &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout:   time.Duration(5*count) * time.Second,
			ExpectContinueTimeout: time.Duration(count) * time.Second,
		}
		client := &http.Client{Transport: tr, Timeout: timeout}
		if _, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/api/v3", cOpts.ApiPort)); err == nil {
			return
		} else {
			log.Printf("%v", err)
		}
		time.Sleep(time.Second * time.Duration(count-1))
	}
	log.Fatalf("ERROR: API failed to come up in a timely fashion! (we gave it around 63 seconds)")
}

func bootstrapPlugins(
	localLogger *log.Logger,
	l logger.Logger,
	cOpts *ProgOpts,
	secretStore store.Store) (*midlayer.PluginController, map[string]*models.PluginProvider, error) {
	localLogger.Printf("Bootstrapping plugins")
	scratchStore, err := backend.InitDataStack(cOpts.SaasContentRoot, cOpts.FileRoot, l)
	if err != nil {
		return nil, nil, err
	}
	// This is intended to jsut serve license information to the plugins for define
	publishers := backend.NewPublishers(localLogger)
	dt := backend.NewDataTracker(scratchStore,
		secretStore,
		cOpts.FileRoot,
		cOpts.LogRoot,
		"127.0.0.1",
		cOpts.ForceStatic,
		cOpts.StaticPort,
		cOpts.ApiPort,
		cOpts.HaId,
		l,
		map[string]string{
			"debugBootEnv":        cOpts.DebugBootEnv,
			"debugDhcp":           cOpts.DebugDhcp,
			"debugRenderer":       cOpts.DebugRenderer,
			"debugFrontend":       cOpts.DebugFrontend,
			"debugPlugins":        cOpts.DebugPlugins,
			"defaultStage":        cOpts.DefaultStage,
			"logLevel":            cOpts.DefaultLogLevel,
			"defaultBootEnv":      cOpts.DefaultBootEnv,
			"unknownBootEnv":      cOpts.UnknownBootEnv,
			"knownTokenTimeout":   fmt.Sprintf("%d", cOpts.KnownTokenTimeout),
			"unknownTokenTimeout": fmt.Sprintf("%d", cOpts.UnknownTokenTimeout),
			"baseTokenSecret":     cOpts.BaseTokenSecret,
			"systemGrantorSecret": cOpts.SystemGrantorSecret,
		},
		publishers)
	pc, err := midlayer.InitPluginController(cOpts.PluginRoot, cOpts.PluginCommRoot, l)
	if err != nil {
		return nil, nil, err
	}
	fe := frontend.NewFrontend(dt, l,
		"127.0.0.1",
		cOpts.ApiPort, cOpts.StaticPort, cOpts.DhcpPort, cOpts.BinlPort,
		cOpts.FileRoot,
		cOpts.LocalUI, cOpts.UIUrl, nil, publishers, []string{cOpts.DrpId, cOpts.DrpId, cOpts.HaId}, pc,
		cOpts.DisableDHCP, cOpts.DisableTftpServer, cOpts.DisableProvisioner, cOpts.DisableBINL,
		cOpts.SaasContentRoot)
	srv := &http.Server{
		TLSConfig: &tls.Config{},
		Addr:      fmt.Sprintf("127.0.0.1:%d", cOpts.ApiPort),
		Handler:   fe.MgmtApi,
	}
	go srv.ListenAndServeTLS(cOpts.TlsCertFile, cOpts.TlsKeyFile)
	defer srv.Shutdown(context.Background())
	waitOnApi(cOpts)
	rt := dt.Request(l)
	providers, err := pc.Define(rt, cOpts.FileRoot)
	localLogger.Printf("Plugins bootstrapped")
	return pc, providers, err
}

func server(localLogger *log.Logger, cOpts *ProgOpts) error {
	onlyICanReadThings()
	if err := processArgs(localLogger, cOpts); err != nil {
		return err
	}
	services := make([]midlayer.Service, 0, 0)

	// HA waits here.
	if cOpts.HaEnabled {
		midlayer.RemoveIP(cOpts.HaAddress, cOpts.HaInterface)

		leader := midlayer.BecomeLeader(localLogger)
		services = append(services, leader)

		if err := midlayer.AddIP(cOpts.HaAddress, cOpts.HaInterface); err != nil {
			return fmt.Errorf("Unable to add address: %v", err)
		}
	}
	buf, err := makeLogBuffer(localLogger, cOpts)
	if err != nil {
		return err
	}
	var secretStore store.Store
	if u, perr := url.Parse(cOpts.SecretsType); perr == nil && u.Scheme != "" {
		secretStore, err = store.Open(cOpts.SecretsType)
	} else {
		secretStore, err = store.Open(fmt.Sprintf("%s://%s", cOpts.SecretsType, cOpts.SecretsRoot))
	}
	if err != nil {
		return fmt.Errorf("Unable to open secrets store: %v", err)
	}

	// No DrpId - get a mac address
	intfs, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("Error getting interfaces for DrpId: %v", err)
	}

	var localId string
	for _, intf := range intfs {
		if (intf.Flags & net.FlagLoopback) == net.FlagLoopback {
			continue
		}
		if (intf.Flags & net.FlagUp) != net.FlagUp {
			continue
		}
		if strings.HasPrefix(intf.Name, "veth") {
			continue
		}
		localId = intf.HardwareAddr.String()
		break
	}
	if cOpts.DrpId == "" {
		cOpts.DrpId = localId
	}
	if cOpts.HaId == "" {
		cOpts.HaId = cOpts.DrpId
	}
	pc, providers, err := bootstrapPlugins(localLogger, buf.Log("bootstrap"), cOpts, secretStore)
	if err != nil {
		return fmt.Errorf("Error bootstrapping plugins: %v", err)
	}
	providerStores := map[string]store.Store{}
	for k, v := range providers {
		if ps, err := v.Store(); err != nil {
			return fmt.Errorf("Error getting Store from plugin %s: %v", k, err)
		} else {
			providerStores[k] = ps
		}
	}

	localLogger.Printf("Starting metrics server")
	svc, err := midlayer.ServeMetrics(fmt.Sprintf(":%d", cOpts.MetricsPort), buf.Log("metrics"))
	if err != nil {
		return fmt.Errorf("Error starting metrics server: %v", err)
	}
	services = append(services, svc)

	if cOpts.PromGwUrl != "" {
		ppg := utils.NewPrometheusPushGateway(buf.Log("promgateway"), cOpts.PromGwUrl,
			fmt.Sprintf("http://127.0.0.1:%d/metrics", cOpts.MetricsPort),
			time.Duration(cOpts.PromInterval)*time.Second)
		services = append(services, ppg)
	}

	// Make data store
	dtStore, err := backend.DefaultDataStack(cOpts.DataRoot, cOpts.BackEndType,
		cOpts.LocalContent, cOpts.DefaultContent, cOpts.SaasContentRoot, cOpts.FileRoot,
		buf.Log("backend"), providerStores)
	if err != nil {
		return fmt.Errorf("Unable to create DataStack: %v", err)
	}
	// We have a backend, now get default assets
	publishers := backend.NewPublishers(localLogger)

	dt := backend.NewDataTracker(dtStore,
		secretStore,
		cOpts.FileRoot,
		cOpts.LogRoot,
		cOpts.OurAddress,
		cOpts.ForceStatic,
		cOpts.StaticPort,
		cOpts.ApiPort,
		cOpts.HaId,
		buf.Log("backend"),
		map[string]string{
			"debugBootEnv":        cOpts.DebugBootEnv,
			"debugDhcp":           cOpts.DebugDhcp,
			"debugRenderer":       cOpts.DebugRenderer,
			"debugFrontend":       cOpts.DebugFrontend,
			"debugPlugins":        cOpts.DebugPlugins,
			"defaultStage":        cOpts.DefaultStage,
			"logLevel":            cOpts.DefaultLogLevel,
			"defaultBootEnv":      cOpts.DefaultBootEnv,
			"unknownBootEnv":      cOpts.UnknownBootEnv,
			"knownTokenTimeout":   fmt.Sprintf("%d", cOpts.KnownTokenTimeout),
			"unknownTokenTimeout": fmt.Sprintf("%d", cOpts.UnknownTokenTimeout),
			"baseTokenSecret":     cOpts.BaseTokenSecret,
			"systemGrantorSecret": cOpts.SystemGrantorSecret,
		},
		publishers)

	if cOpts.CleanupCorrupt {
		dt.Cleanup = true
	}
	services = append(services, pc)

	fe := frontend.NewFrontend(dt, buf.Log("frontend"),
		cOpts.OurAddress,
		cOpts.ApiPort, cOpts.StaticPort, cOpts.DhcpPort, cOpts.BinlPort,
		cOpts.FileRoot,
		cOpts.LocalUI, cOpts.UIUrl, nil, publishers, []string{cOpts.DrpId, localId, cOpts.HaId}, pc,
		cOpts.DisableDHCP, cOpts.DisableTftpServer, cOpts.DisableProvisioner, cOpts.DisableBINL,
		cOpts.SaasContentRoot)
	fe.TftpPort = cOpts.TftpPort
	fe.BinlPort = cOpts.BinlPort
	fe.NoBinl = cOpts.DisableBINL
	backend.SetLogPublisher(buf, publishers)
	pc.AddStorageType = fe.AddStorageType

	if _, err := os.Stat(cOpts.TlsCertFile); os.IsNotExist(err) {
		if err = buildKeys(cOpts.CurveOrBits, cOpts.TlsCertFile, cOpts.TlsKeyFile); err != nil {
			return fmt.Errorf("Error building certs: %v", err)
		}
	}

	if !cOpts.DisableTftpServer {
		localLogger.Printf("Starting TFTP server")
		svc, err := midlayer.ServeTftp(
			fmt.Sprintf(":%d", cOpts.TftpPort),
			dt.FS.TftpResponder(),
			buf.Log("static"),
			publishers)
		if err != nil {
			return fmt.Errorf("Error starting TFTP server: %v", err)
		}
		services = append(services, svc)
	}

	if !cOpts.DisableProvisioner {
		localLogger.Printf("Starting static file server")
		svc, err := midlayer.ServeStatic(
			fmt.Sprintf(":%d", cOpts.StaticPort),
			dt.FS, buf.Log("static"),
			publishers)
		if err != nil {
			return fmt.Errorf("Error starting static file server: %v", err)
		}
		services = append(services, svc)
	}

	if !cOpts.DisableDHCP {
		localLogger.Printf("Starting DHCP server")
		svc, err := midlayer.StartDhcpHandler(
			dt,
			buf.Log("dhcp"),
			cOpts.DhcpInterfaces,
			cOpts.DhcpPort,
			publishers,
			false,
			cOpts.FakePinger)
		if err != nil {
			return fmt.Errorf("Error starting DHCP server: %v", err)
		}
		services = append(services, svc)

		if !cOpts.DisableBINL {
			localLogger.Printf("Starting PXE/BINL server")
			svc, err := midlayer.StartDhcpHandler(
				dt,
				buf.Log("dhcp"),
				cOpts.DhcpInterfaces,
				cOpts.BinlPort,
				publishers,
				true,
				cOpts.FakePinger)
			if err != nil {
				return fmt.Errorf("Error starting PXE/BINL server: %v", err)
			}
			services = append(services, svc)
		}
	}

	var cfg *tls.Config
	if !cOpts.UseOldCiphers {
		cfg = &tls.Config{
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			},
		}
	}
	srv := &http.Server{
		TLSConfig: cfg,
		Addr:      fmt.Sprintf(":%d", cOpts.ApiPort),
		Handler:   fe.MgmtApi,
		ConnState: func(n net.Conn, cs http.ConnState) {
			if cs == http.StateActive {
				l := fe.Logger.Fork().SetPrincipal("cacher")
				laddr, lok := n.LocalAddr().(*net.TCPAddr)
				raddr, rok := n.RemoteAddr().(*net.TCPAddr)
				if lok && rok && cs == http.StateActive {
					backend.AddToCache(l, laddr.IP, raddr.IP)
				}
			}
		},
	}
	services = append(services, srv)

	// Handle SIGHUP, SIGINT and SIGTERM.
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGABRT)

	watchDone := make(chan struct{})

	go func() {
		waitOnApi(cOpts)
		// Start the controller now that we have a frontend to front.
		pc.Start(dt, providers, publishers)

		for {
			s := <-ch
			log.Println(s)

			switch s {
			case syscall.SIGABRT:
				if cOpts.HaEnabled {
					localLogger.Printf("Removing VIP: %s:%s\n", cOpts.HaInterface, cOpts.HaAddress)
					midlayer.RemoveIP(cOpts.HaAddress, cOpts.HaInterface)
				}
				localLogger.Printf("Dumping all goroutine stacks")
				pprof.Lookup("goroutine").WriteTo(os.Stderr, 2)
				localLogger.Printf("Dumping stacks of contested mutexes")
				pprof.Lookup("mutex").WriteTo(os.Stderr, 2)
				localLogger.Printf("Exiting")
				os.Exit(1)
			case syscall.SIGHUP:
				localLogger.Println("Reloading data stores...")
				rt := dt.Request(dt.Logger)
				providers, err = pc.Define(rt, cOpts.FileRoot)
				if err != nil {
					localLogger.Printf("Unable to load data stores from plugins: %v", err)
					continue
				}
				providerStores = map[string]store.Store{}
				xit := false
				for k, v := range providers {
					if ps, err := v.Store(); err != nil {
						localLogger.Printf("Error getting Store from plugin %s: %v", k, err)
						xit = true
					} else {
						providerStores[k] = ps
					}
				}
				if xit {
					continue
				}
				// Make data store - THIS IS BAD if datastore is memory.
				dtStore, err := backend.DefaultDataStack(cOpts.DataRoot, cOpts.BackEndType,
					cOpts.LocalContent, cOpts.DefaultContent, cOpts.SaasContentRoot, cOpts.FileRoot,
					buf.Log("backend"), providerStores)
				if err != nil {
					localLogger.Printf("Unable to create new DataStack on SIGHUP: %v", err)
				} else {

					rt.AllLocked(func(d backend.Stores) {
						dt.ReplaceBackend(rt, dtStore)
					})
					localLogger.Println("Reload Complete")
				}
			case syscall.SIGTERM, syscall.SIGINT:
				if cOpts.HaEnabled {
					localLogger.Printf("Removing VIP: %s:%s\n", cOpts.HaInterface, cOpts.HaAddress)
					midlayer.RemoveIP(cOpts.HaAddress, cOpts.HaInterface)
				}
				// Stop the service gracefully.
				for _, svc := range services {
					localLogger.Println("Shutting down server...")
					if err := svc.Shutdown(context.Background()); err != nil {
						localLogger.Printf("could not shutdown: %v", err)
					}
				}
				if watchDone != nil {
					close(watchDone)
				}
				break
			}
		}
	}()

	go func() {
		localLogger.Printf("Starting API server")
		fe.ApiGroup.Any("/plugin-apis/:plugin/*path", midlayer.ReverseProxy(pc))
		if err = srv.ListenAndServeTLS(cOpts.TlsCertFile, cOpts.TlsKeyFile); err != http.ErrServerClosed {
			// Stop the service gracefully.
			for _, svc := range services {
				localLogger.Println("Shutting down server...")
				if err := svc.Shutdown(context.Background()); err != http.ErrServerClosed {
					localLogger.Printf("could not shutdown: %v", err)
				}
			}
			if watchDone != nil {
				close(watchDone)
			}
		}
	}()

	err = watchSelf(localLogger, watchDone, services)
	if err != nil {
		err = fmt.Errorf("Error starting watcher service: %v", err)
	}
	return err
}

// Server takes the start up options and runs a DRP server.  This function
// will not return unless an error or shutdown signal is received.
func Server(cOpts *ProgOpts) {
	localLogger := log.New(os.Stderr, "dr-provision", log.LstdFlags|log.Lmicroseconds|log.LUTC)
	if err := server(localLogger, cOpts); err != nil {
		localLogger.Fatalln(err.Error())
	}
	localLogger.Printf("Exiting")
}
