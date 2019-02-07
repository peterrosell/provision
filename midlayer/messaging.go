package midlayer

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/digitalrebar/logger"
)

var globalSocketId int64 = 1

type PluginClient struct {
	logger.Logger
	pc       *PluginController
	plugin   string
	provider string
	cmd      *exec.Cmd
	stderr   io.ReadCloser
	done     int64
	lock     sync.Mutex

	publock   sync.Mutex
	inflight  int
	unloading bool

	socketId int64
	client   *http.Client
}

func (pc *PluginClient) readLog(name string, com io.ReadCloser) {
	atomic.AddInt64(&pc.done, 1)
	pc.Tracef("readLog: Starting log reader %s(%s)\n", pc.plugin, name)
	// read command's com line by line - for logging
	in := bufio.NewScanner(com)
	for in.Scan() {
		// XXX: NoPublish these until we get json logging setup.
		// The problem is that publish calls generate logging that generate Publish calls
		// This loops (but doesn't hang).  So, don't event these, but log them.
		pc.NoPublish().Infof("Plugin %s(%s): %s", pc.plugin, name, in.Text())
	}
	if err := in.Err(); err != nil {
		pc.Errorf("Plugin %s(%s): error: %s", pc.plugin, name, err)
	}
	pc.Tracef("readLog: Finished log reader %s(%s)\n", pc.plugin, name)
	atomic.AddInt64(&pc.done, -1)
}

func (pc *PluginClient) Reserve() error {
	pc.NoPublish().Tracef("Reserve: started\n")
	pc.publock.Lock()
	defer pc.publock.Unlock()

	if pc.unloading {
		err := fmt.Errorf("Publish not available %s: unloading\n", pc.plugin)
		pc.NoPublish().Tracef("Reserve: finished: %v\n", err)
		return err
	}
	pc.inflight += 1
	pc.NoPublish().Tracef("Reserve: finished: %d\n", pc.inflight)
	return nil
}

func (pc *PluginClient) Release() {
	pc.NoPublish().Tracef("Release: started\n")
	pc.publock.Lock()
	defer pc.publock.Unlock()
	pc.inflight -= 1
	pc.NoPublish().Tracef("Release: finished: %d\n", pc.inflight)
}

func (pc *PluginClient) Unload() {
	pc.Tracef("Unload: started\n")
	pc.publock.Lock()
	pc.unloading = true
	count := 0
	for pc.inflight != 0 {
		if count%100 == 0 {
			pc.Tracef("Unload: waiting - %d\n", pc.inflight)
		}
		pc.publock.Unlock()
		count += 1
		time.Sleep(time.Millisecond * 15)
		pc.publock.Lock()
	}
	pc.publock.Unlock()
	pc.Tracef("Unload: finished\n")
	return
}

func NewPluginClient(pc *PluginController, pluginCommDir, plugin, provider string, l logger.Logger, apiURL, staticURL, token, path string) (answer *PluginClient, theErr error) {
	id := atomic.AddInt64(&globalSocketId, 1)

	answer = &PluginClient{pc: pc, plugin: plugin, Logger: l, socketId: id, provider: provider}
	answer.Debugf("Initialzing Plugin: %s\n", plugin)

	retSocketPath := fmt.Sprintf("%s/%s.fromPlugin.%d", pluginCommDir, plugin, id)
	socketPath := fmt.Sprintf("%s/%s.toPlugin.%d", pluginCommDir, plugin, id)

	// Start server side.
	answer.pluginServer(retSocketPath)

	// Setup client.
	answer.cmd = exec.Command(path, "listen", socketPath, retSocketPath)

	// Setup env vars to run plugin - auth should be parameters.
	env := os.Environ()
	env = append(env, fmt.Sprintf("RS_ENDPOINT=%s", apiURL))
	env = append(env, fmt.Sprintf("RS_FILESERVER=%s", staticURL))
	env = append(env, fmt.Sprintf("RS_TOKEN=%s", token))
	answer.cmd.Env = env

	plugintmppath := fmt.Sprintf("%s/plugin-tmp", filepath.Dir(pc.pluginDir))
	os.MkdirAll(plugintmppath, 0700)
	answer.cmd.Dir = plugintmppath

	var err2 error
	answer.stderr, err2 = answer.cmd.StderrPipe()
	if err2 != nil {
		return nil, err2
	}

	// We need so for the ready call.
	so, err2 := answer.cmd.StdoutPipe()
	if err2 != nil {
		return nil, err2
	}

	// Close stdin, we don't need it.
	if si, err2 := answer.cmd.StdinPipe(); err2 != nil {
		return nil, err2
	} else {
		si.Close()
	}

	// Start the err reader.
	go answer.readLog("se", answer.stderr)

	// Start the plugin
	answer.Debugf("Start Plugin: %s\n", plugin)
	if err := answer.cmd.Start(); err != nil {
		err2 := fmt.Errorf("Failed to start plugin - didn't start: %v", err)
		l.Errorf("%v\n", err2)
		return nil, err2
	}

	// Wait for plugin to be listening
	answer.Debugf("Wait for ready: %v\n", answer.cmd.Process.Pid)
	failed := false
	in := bufio.NewScanner(so)
	for in.Scan() {
		s := in.Text()
		if s == "READY!" {
			break
		}
		if s == "Failed" {
			failed = true
			break
		}
		// Log each line until ready or fail
		l.Infof("Plugin %s: start-up: %s", answer.plugin, s)
	}
	if err := in.Err(); err != nil {
		l.Errorf("Plugin %s: start-up error: %s", answer.plugin, err)
		failed = true
	}
	if failed {
		answer.Stop()
		err := fmt.Errorf("Failed to start plugin - didn't respond cleanly")
		l.Errorf("%v\n", err)
		return nil, err
	}
	// Start so reader to make sure nothing else gets stashed in the pipe
	go answer.readLog("so", so)

	// Get HTTP2 client on our socket.
	answer.client = &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}

	answer.Debugf("Initialzing Plugin: complete %s\n", plugin)
	return
}
