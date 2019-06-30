package backend

import (
	"net"
	"net/http"
	"os"

	"github.com/digitalrebar/logger"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/provision/plugin/mux"
)

func publishHandler(w http.ResponseWriter, r *http.Request, pc *PluginClient) {
	var event models.Event
	if !mux.AssureDecode(w, r, &event) {
		return
	}
	resp := models.Error{Code: http.StatusOK}
	if err := pc.pc.Request().PublishEvent(&event); err != nil {
		resp.Code = 409
		resp.AddError(err)
	}
	mux.JsonResponse(w, resp.Code, resp)
}

func logHandler(w http.ResponseWriter, r *http.Request, pc *PluginClient) {
	var line logger.Line
	if !mux.AssureDecode(w, r, &line) {
		return
	}
	if line.Level == logger.Fatal || line.Level == logger.Panic {
		line.Level = logger.Error
	}
	pc.AddLine(&line)
	mux.JsonResponse(w, 204, nil)
}

func leavingHandler(w http.ResponseWriter, r *http.Request, pc *PluginClient) {
	var err models.Error
	if !mux.AssureDecode(w, r, &err) {
		return
	}
	if err.Code == 403 {
		pc.pc.lock.Lock()
		defer pc.pc.lock.Unlock()
		rt := pc.pc.Request()
		pc.pc.removePluginProvider(rt, pc.provider)
	} else {
		pc.lock.Lock()
		defer pc.lock.Unlock()
		if r, ok := pc.pc.runningPlugins[pc.plugin]; ok {
			pc.pc.Request().PublishEvent(models.EventFor(r.Plugin, "stop"))
		}
	}
	mux.JsonResponse(w, 204, nil)
}

func (pc *PluginClient) pluginServer(commPath string) {
	pc.Tracef("pluginServer: Starting com server: %s(%s)\n", pc.plugin, commPath)
	pmux := mux.New(pc.NoPublish())
	pmux.Handle("/api-server-plugin/v3/publish",
		func(w http.ResponseWriter, r *http.Request) { publishHandler(w, r, pc) })
	pmux.Handle("/api-server-plugin/v3/leaving",
		func(w http.ResponseWriter, r *http.Request) { leavingHandler(w, r, pc) })
	pmux.Handle("/api-server-plugin/v3/log",
		func(w http.ResponseWriter, r *http.Request) { logHandler(w, r, pc) })
	go func() {
		os.Remove(commPath)
		sock, err := net.Listen("unix", commPath)
		if err != nil {
			return
		}
		defer sock.Close()
		if err := http.Serve(sock, pmux); err != nil {
			pc.Errorf("pluginServer: Finished (error) com server: %s(%s): %v\n", pc.plugin, commPath, err)
		} else {
			pc.Tracef("pluginServer: Finished com server: %s(%s)\n", pc.plugin, commPath)
		}
	}()
}
