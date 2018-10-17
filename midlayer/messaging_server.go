package midlayer

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/digitalrebar/logger"
	"github.com/digitalrebar/provision/backend"
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

func objectGetHandler(w http.ResponseWriter, r *http.Request, pc *PluginClient) {
	path := r.URL.Path
	path = strings.TrimPrefix(path, "/api-server-plugin/v3/objects/")
	var answer interface{}
	if !strings.Contains(path, "/") {
		answer = []interface{}{}

		rt := pc.pc.Request(path)
		arr := []models.Model{}
		rt.Do(func(d backend.Stores) {
			mainIndex := &d(path).Index
			// totalCount = mainIndex.Count()
			// count = mainIndex.Count()

			items := mainIndex.Items()
			for _, item := range items {
				arr = append(arr, models.Clone(item))
			}
		})
		answer = arr
	} else {
		parts := strings.Split(path, "/")
		if len(parts) != 2 {
			e := models.NewError("plugin-mux", 404, fmt.Sprintf("Failed to find: %s", path))
			mux.JsonResponse(w, 404, e)
			return
		}

		rt := pc.pc.Request(parts[0])
		rt.Do(func(d backend.Stores) {
			obj := rt.Find(parts[0], parts[1])
			if obj != nil {
				// This forces it back to a models object
				answer = models.Clone(obj)
			}
		})
		if answer == nil {
			e := models.NewError("plugin-mux", 404, fmt.Sprintf("Not found: %s", path))
			mux.JsonResponse(w, 404, e)
			return
		}
	}
	mux.JsonResponse(w, 200, answer)
}

func objectPostHandler(w http.ResponseWriter, r *http.Request, pc *PluginClient) {
	pc.Errorf("pluginServer: post oh = %v\n", r)
	path := r.URL.Path
	path = strings.TrimPrefix(path, "/api-server-plugin/v3/objects/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		e := models.NewError("plugin-mux", 404, fmt.Sprintf("Failed to save (bad path): %s", path))
		mux.JsonResponse(w, 404, e)
		return
	}

	var m models.RawModel
	if !mux.AssureDecode(w, r, &m) {
		return
	}

	if m.Type == "" {
		m.Type = parts[0]
	}

	var answer interface{}
	var e error
	rt := pc.pc.Request(parts[0])
	rt.Do(func(d backend.Stores) {
		answer = rt.Find(parts[0], parts[1])
		if answer != nil {
			pc.Errorf("GREG: Updating %+v in object plugin\n", m)
			_, e = rt.Update(&m)
		} else {
			pc.Errorf("GREG: Creating %+v in object plugin\n", m)
			_, e = rt.Create(&m)
		}
		answer = &m
	})
	if e != nil {
		be := models.NewError("plugin-mux", 400, fmt.Sprintf("Failed to save: %s: %v", path, e))
		mux.JsonResponse(w, 400, be)
		return
	}
	mux.JsonResponse(w, 200, answer)
}

func objectDeleteHandler(w http.ResponseWriter, r *http.Request, pc *PluginClient) {
	pc.Errorf("pluginServer: delete oh = %v\n", r)
	path := r.URL.Path
	path = strings.TrimPrefix(path, "/api-server-plugin/v3/objects/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		e := models.NewError("plugin-mux", 404, fmt.Sprintf("Failed to delete (bad path): %s", path))
		mux.JsonResponse(w, 404, e)
		return
	}
	var e *models.Error
	rt := pc.pc.Request(parts[0])
	rt.Do(func(d backend.Stores) {
		m := rt.Find(parts[0], parts[1])
		if m == nil {
			e = models.NewError("plugin-mux", 404, fmt.Sprintf("Failed to delete (not found): %s", path))
		} else {
			_, err := rt.Remove(m)
			if err != nil {
				e = models.NewError("plugin-mux", 400, fmt.Sprintf("Failed to delete: %s: %v", path, e))
			}
		}
	})
	if e != nil {
		mux.JsonResponse(w, e.Code, e)
		return
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
	pmux.HandleMap("/api-server-plugin/v3/objects/", map[string]http.HandlerFunc{
		"GET":    func(w http.ResponseWriter, r *http.Request) { objectGetHandler(w, r, pc) },
		"POST":   func(w http.ResponseWriter, r *http.Request) { objectPostHandler(w, r, pc) },
		"DELETE": func(w http.ResponseWriter, r *http.Request) { objectDeleteHandler(w, r, pc) },
	})
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
