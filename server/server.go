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
	DisableTftpServer   bool   `long:"disable-tftp" description:"Disable TFTP server"`
	DisableProvisioner  bool   `long:"disable-provisioner" description:"Disable provisioner"`
	DisableDHCP         bool   `long:"disable-dhcp" description:"Disable DHCP server"`
	DisableBINL         bool   `long:"disable-pxe" description:"Disable PXE/BINL server"`
	MetricsPort         int    `long:"metrics-port" description:"Port the metrics HTTP server should listen on" default:"8080"`
	StaticPort          int    `long:"static-port" description:"Port the static HTTP file server should listen on" default:"8091"`
	TftpPort            int    `long:"tftp-port" description:"Port for the TFTP server to listen on" default:"69"`
	ApiPort             int    `long:"api-port" description:"Port for the API server to listen on" default:"8092"`
	DhcpPort            int    `long:"dhcp-port" description:"Port for the DHCP server to listen on" default:"67"`
	BinlPort            int    `long:"binl-port" description:"Port for the PXE/BINL server to listen on" default:"4011"`
	UnknownTokenTimeout int    `long:"unknown-token-timeout" description:"The default timeout in seconds for the machine create authorization token" default:"600"`
	KnownTokenTimeout   int    `long:"known-token-timeout" description:"The default timeout in seconds for the machine update authorization token" default:"3600"`
	OurAddress          string `long:"static-ip" description:"IP address to advertise for the static HTTP file server" default:""`
	ForceStatic         bool   `long:"force-static" description:"Force the system to always use the static IP."`

	BackEndType    string `long:"backend" description:"Storage to use for persistent data. Can be either 'consul', 'directory', or a store URI" default:"directory"`
	SecretsType    string `long:"secrets" description:"Storage to use for persistent data. Can be either 'consul', 'directory', or a store URI.  Will default to being the same as 'backend'" default:""`
	LocalContent   string `long:"local-content" description:"Storage to use for local overrides." default:"directory:///etc/dr-provision?codec=yaml"`
	DefaultContent string `long:"default-content" description:"Store URL for local content" default:"file:///usr/share/dr-provision/default.yaml?codec=yaml"`

	BaseRoot        string `long:"base-root" description:"Base directory for other root dirs." default:"/var/lib/dr-provision"`
	DataRoot        string `long:"data-root" description:"Location we should store runtime information in" default:"digitalrebar"`
	SecretsRoot     string `long:"secrets-root" description:"Location we should store encrypted parameter private keys in" default:"secrets"`
	PluginRoot      string `long:"plugin-root" description:"Directory for plugins" default:"plugins"`
	PluginCommRoot  string `long:"plugin-comm-root" description:"Directory for the communications for plugins" default:"/var/run"`
	LogRoot         string `long:"log-root" description:"Directory for job logs" default:"job-logs"`
	SaasContentRoot string `long:"saas-content-root" description:"Directory for additional content" default:"saas-content"`
	FileRoot        string `long:"file-root" description:"Root of filesystem we should manage" default:"tftpboot"`
	ReplaceRoot     string `long:"replace-root" description:"Root of filesystem we should use to replace embedded assets" default:"replace"`

	LocalUI        string `long:"local-ui" description:"Root of Local UI Pages" default:"ux"`
	UIUrl          string `long:"ui-url" description:"URL to redirect to UI" default:"https://portal.rackn.io"`
	DhcpInterfaces string `long:"dhcp-ifs" description:"Comma-separated list of interfaces to listen for DHCP packets" default:""`
	DefaultStage   string `long:"default-stage" description:"The default stage for the nodes" default:"none"`
	DefaultBootEnv string `long:"default-boot-env" description:"The default bootenv for the nodes" default:"local"`
	UnknownBootEnv string `long:"unknown-boot-env" description:"The unknown bootenv for the system.  Should be \"ignore\" or \"discovery\"" default:"ignore"`

	DebugBootEnv  string `long:"debug-bootenv" description:"Debug level for the BootEnv System" default:"warn"`
	DebugDhcp     string `long:"debug-dhcp" description:"Debug level for the DHCP Server" default:"warn"`
	DebugRenderer string `long:"debug-renderer" description:"Debug level for the Template Renderer" default:"warn"`
	DebugFrontend string `long:"debug-frontend" description:"Debug level for the Frontend" default:"warn"`
	DebugPlugins  string `long:"debug-plugins" description:"Debug level for the Plug-in layer" default:"warn"`
	TlsKeyFile    string `long:"tls-key" description:"The TLS Key File" default:"server.key"`
	TlsCertFile   string `long:"tls-cert" description:"The TLS Cert File" default:"server.crt"`
	UseOldCiphers bool   `long:"use-old-ciphers" description:"Use Original Less Secure Cipher List"`
	DrpId         string `long:"drp-id" description:"The id of this Digital Rebar Provision instance" default:""`
	CurveOrBits   string `long:"cert-type" description:"Type of cert to generate. values are: P224, P256, P384, P521, RSA, or <number of RSA bits>" default:"P384"`

	BaseTokenSecret     string `long:"base-token-secret" description:"Auth Token secret to allow revocation of all tokens" default:""`
	SystemGrantorSecret string `long:"system-grantor-secret" description:"Auth Token secret to allow revocation of all Machine tokens" default:""`
	FakePinger          bool   `hidden:"true" long:"fake-pinger"`
	DefaultLogLevel     string `long:"log-level" description:"Level to log messages at" default:"warn"`

	HaEnabled   bool   `long:"ha-enabled" description:"Enable HA"`
	HaAddress   string `long:"ha-address" description:"IP address to advertise as our HA address" default:""`
	HaInterface string `long:"ha-interface" description:"Interface to put the VIP on for HA" default:""`

	PromGwUrl      string `long:"prometheus-gateway-url" description:"URL to push metrics to" default:""`
	PromInterval   int    `long:"prometheus-interval" description:"Duration in seconds to push metrics" default:"5"`
	CleanupCorrupt bool   `long:"cleanup" description:"Clean up corrupted writable data.  Only use when directed."`
}

func mkdir(d string) error {
	return os.MkdirAll(d, 0755)
}

// Server takes the start up options and runs a DRP server.  This function
// will not return unless an error or shutdown signal is received.
func Server(cOpts *ProgOpts) {
	localLogger := log.New(os.Stderr, "dr-provision", log.LstdFlags|log.Lmicroseconds|log.LUTC)
	localLogger.Fatalf(server(localLogger, cOpts))
}

func server(localLogger *log.Logger, cOpts *ProgOpts) string {
	onlyICanReadThings()
	var err error

	if cOpts.VersionFlag {
		return fmt.Sprintf("Version: %s", provision.RSVersion)
	}
	localLogger.Printf("Version: %s\n", provision.RSVersion)

	// Make base root dir
	if err = mkdir(cOpts.BaseRoot); err != nil {
		return fmt.Sprintf("Error creating required directory %s: %v", cOpts.BaseRoot, err)
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
		return fmt.Sprintf("PluginCommRoot Must be less than 70 characters")
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
		return fmt.Sprintf("Error creating required directory %s: %v", cOpts.FileRoot, err)
	}
	if err = mkdir(path.Join(cOpts.FileRoot, "files")); err != nil {
		return fmt.Sprintf("Error creating required directory %s: %v", cOpts.FileRoot, err)
	}
	if err = mkdir(cOpts.ReplaceRoot); err != nil {
		return fmt.Sprintf("Error creating required directory %s: %v", cOpts.ReplaceRoot, err)
	}
	if err = mkdir(cOpts.PluginRoot); err != nil {
		return fmt.Sprintf("Error creating required directory %s: %v", cOpts.PluginRoot, err)
	}
	if err = mkdir(cOpts.PluginCommRoot); err != nil {
		return fmt.Sprintf("Error creating required directory %s: %v", cOpts.PluginCommRoot, err)
	}
	if cOpts.BackEndType == "directory" {
		if err = mkdir(cOpts.DataRoot); err != nil {
			return fmt.Sprintf("Error creating required directory %s: %v", cOpts.DataRoot, err)
		}
	}
	if err = mkdir(cOpts.LogRoot); err != nil {
		return fmt.Sprintf("Error creating required directory %s: %v", cOpts.LogRoot, err)
	}
	if err = mkdir(cOpts.LocalUI); err != nil {
		return fmt.Sprintf("Error creating required directory %s: %v", cOpts.LocalUI, err)
	}
	if err = mkdir(cOpts.SaasContentRoot); err != nil {
		return fmt.Sprintf("Error creating required directory %s: %v", cOpts.SaasContentRoot, err)
	}
	if cOpts.SecretsType == "directory" {
		if err = mkdir(cOpts.SecretsRoot); err != nil {
			return fmt.Sprintf("Error creating required directory %s: %v", cOpts.SecretsRoot, err)
		}
	}
	// Validate HA args - Assumes a local consul server running talking to the "cluster"
	if cOpts.HaEnabled {
		if cOpts.SecretsType != "consul" || cOpts.BackEndType != "consul" {
			return fmt.Sprintf("Error: HA must be run on consul backends: %s, %s", cOpts.SecretsType, cOpts.BackEndType)
		}

		if cOpts.HaAddress == "" {
			return "Error: HA must specify a VIP that DRP will move around"
		}

		if cOpts.HaInterface == "" {
			return "Error: HA must specify an interface for the VIP that DRP will move around"
		}

		ip := net.ParseIP(cOpts.HaAddress)
		if ip == nil {
			return fmt.Sprintf("Error: HA must be an IP address: %s", cOpts.HaAddress)
		}

		if cOpts.OurAddress != "" {
			oip := net.ParseIP(cOpts.OurAddress)
			if oip == nil {
				return fmt.Sprintf("Error: OurAddress must be an IP address: %s", cOpts.OurAddress)
			}
			if !oip.Equal(ip) {
				return fmt.Sprintf("Error: HA Address must match OurAddress. %s != %s", cOpts.HaAddress, cOpts.OurAddress)
			}
		} else {
			cOpts.OurAddress = cOpts.HaAddress
		}
	}

	localLogger.Printf("Extracting Default Assets\n")
	if EmbeddedAssetsExtractFunc != nil {
		localLogger.Printf("Extracting Default Assets\n")
		if err := EmbeddedAssetsExtractFunc(cOpts.ReplaceRoot, cOpts.FileRoot); err != nil {
			return fmt.Sprintf("Unable to extract assets: %v", err)
		}
	}

	services := make([]midlayer.Service, 0, 0)

	// HA waits here.
	if cOpts.HaEnabled {
		midlayer.RemoveIP(cOpts.HaAddress, cOpts.HaInterface)

		leader := midlayer.BecomeLeader(localLogger)
		services = append(services, leader)

		if err := midlayer.AddIP(cOpts.HaAddress, cOpts.HaInterface); err != nil {
			return fmt.Sprintf("Unable to add address: %v", err)
		}
	}

	logLevel, err := logger.ParseLevel(cOpts.DefaultLogLevel)
	if err != nil {
		localLogger.Printf("Invalid log level %s", cOpts.DefaultLogLevel)
		return fmt.Sprintf("Try one of `trace`,`debug`,`info`,`warn`,`error`,`fatal`,`panic`")
	}
	buf := logger.New(localLogger).SetDefaultLevel(logLevel)

	localLogger.Printf("Starting metrics server")
	svc, err := midlayer.ServeMetrics(fmt.Sprintf(":%d", cOpts.MetricsPort), buf.Log("metrics"))
	if err != nil {
		return fmt.Sprintf("Error starting metrics server: %v", err)
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
		buf.Log("backend"))
	if err != nil {
		return fmt.Sprintf("Unable to create DataStack: %v", err)
	}
	var secretStore store.Store
	if u, perr := url.Parse(cOpts.SecretsType); perr == nil && u.Scheme != "" {
		secretStore, err = store.Open(cOpts.SecretsType)
	} else {
		secretStore, err = store.Open(fmt.Sprintf("%s://%s", cOpts.SecretsType, cOpts.SecretsRoot))
	}
	if err != nil {
		return fmt.Sprintf("Unable to open secrets store: %v", err)
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
	// No DrpId - get a mac address
	if cOpts.DrpId == "" {
		intfs, err := net.Interfaces()
		if err != nil {
			return fmt.Sprintf("Error getting interfaces for DrpId: %v", err)
		}

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
			cOpts.DrpId = intf.HardwareAddr.String()
			break
		}
	}

	pc, err := midlayer.InitPluginController(cOpts.PluginRoot, cOpts.PluginCommRoot, dt, publishers)
	if err != nil {
		return fmt.Sprintf("Error starting plugin service: %v", err)
	}
	services = append(services, pc)

	fe := frontend.NewFrontend(dt, buf.Log("frontend"),
		cOpts.OurAddress,
		cOpts.ApiPort, cOpts.StaticPort, cOpts.DhcpPort, cOpts.BinlPort,
		cOpts.FileRoot,
		cOpts.LocalUI, cOpts.UIUrl, nil, publishers, cOpts.DrpId, pc,
		cOpts.DisableDHCP, cOpts.DisableTftpServer, cOpts.DisableProvisioner, cOpts.DisableBINL,
		cOpts.SaasContentRoot)
	fe.TftpPort = cOpts.TftpPort
	fe.BinlPort = cOpts.BinlPort
	fe.NoBinl = cOpts.DisableBINL
	backend.SetLogPublisher(buf, publishers)
	pc.AddStorageType = fe.AddStorageType

	// Start the controller now that we have a frontend to front.
	pc.StartRouter(fe.ApiGroup)

	if _, err := os.Stat(cOpts.TlsCertFile); os.IsNotExist(err) {
		if err = buildKeys(cOpts.CurveOrBits, cOpts.TlsCertFile, cOpts.TlsKeyFile); err != nil {
			return fmt.Sprintf("Error building certs: %v", err)
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
			return fmt.Sprintf("Error starting TFTP server: %v", err)
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
			return fmt.Sprintf("Error starting static file server: %v", err)
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
			return fmt.Sprintf("Error starting DHCP server: %v", err)
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
				return fmt.Sprintf("Error starting PXE/BINL server: %v", err)
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

	go func() {
		// Wait for Api to come up
		for count := 0; count < 5; count++ {
			if count > 0 {
				log.Printf("Waiting for API (%d) to come up...\n", count)
			}
			timeout := time.Duration(5 * time.Second)
			tr := &http.Transport{
				TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
				TLSHandshakeTimeout:   5 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			}
			client := &http.Client{Transport: tr, Timeout: timeout}
			if _, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/api/v3", cOpts.ApiPort)); err == nil {
				break
			}
		}

		// Start the controller now that we have a frontend to front.
		if err := pc.StartController(); err != nil {
			log.Printf("Error starting plugin service: %v", err)
			ch <- syscall.SIGTERM
		}

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
				// Make data store - THIS IS BAD if datastore is memory.
				dtStore, err := backend.DefaultDataStack(cOpts.DataRoot, cOpts.BackEndType,
					cOpts.LocalContent, cOpts.DefaultContent, cOpts.SaasContentRoot, cOpts.FileRoot,
					buf.Log("backend"))
				if err != nil {
					localLogger.Printf("Unable to create new DataStack on SIGHUP: %v", err)
				} else {
					rt := dt.Request(dt.Logger)
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
				break
			}
		}
	}()

	localLogger.Printf("Starting API server")
	if err = srv.ListenAndServeTLS(cOpts.TlsCertFile, cOpts.TlsKeyFile); err != http.ErrServerClosed {
		// Stop the service gracefully.
		for _, svc := range services {
			localLogger.Println("Shutting down server...")
			if err := svc.Shutdown(context.Background()); err != http.ErrServerClosed {
				localLogger.Printf("could not shutdown: %v", err)
			}
		}
		return fmt.Sprintf("Error running API service: %v\n", err)
	}
	return "Exiting"
}
