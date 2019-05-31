package backend

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sync/atomic"
	"time"

	"github.com/digitalrebar/logger"
	"github.com/digitalrebar/provision/models"
)

func (pc *PluginClient) post(l logger.Logger, path string, indata interface{}) ([]byte, error) {
	if data, err := json.Marshal(indata); err != nil {
		return nil, err
	} else {
		resp, err := pc.client.Post(
			fmt.Sprintf("http://unix/api-plugin/v3%s", path),
			"application/json",
			bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		b, e := ioutil.ReadAll(resp.Body)
		if e != nil {
			return nil, e
		}

		if resp.StatusCode >= 400 {
			berr := models.Error{}
			err := json.Unmarshal(b, &berr)
			if err != nil {
				return nil, e
			}
			return nil, &berr
		}
		return b, nil
	}
}

func (pc *PluginClient) get(l logger.Logger, path string) ([]byte, error) {
	l.Tracef("get: started: %s\n", path)
	uri := fmt.Sprintf("http://unix/api-plugin/v3%s", path)
	if resp, err := pc.client.Get(uri); err != nil {
		l.Tracef("get: finished: call %v\n", err)
		return nil, err
	} else {
		defer resp.Body.Close()
		b, e := ioutil.ReadAll(resp.Body)
		l.Tracef("get: finished: %v, %v\n", b, err)
		return b, e
	}
}

func (pc *PluginClient) Stop() error {
	pc.Tracef("Stop: started: %v\n", pc.cmd.Process.Pid)
	// Send stop message
	_, err := pc.post(pc, "/stop", nil)
	if err != nil {
		pc.Errorf("Stop failed: %v\n", err)
	} else {
		pc.Tracef("Stop: post complete\n")
	}

	// Wait for log reader to exit
	if se, err := pc.cmd.StderrPipe(); err == nil {
		se.Close()
	}
	if so, err := pc.cmd.StdoutPipe(); err == nil {
		so.Close()
	}

	pc.Tracef("Stop: waiting for readers to stop\n")
	count := 0
	for atomic.LoadInt64(&pc.done) > 0 && count < 60 {
		pc.Tracef("Stop: waiting for readers to stop: %d\n", count)
		count += 1
		time.Sleep(1 * time.Second)
	}

	// Kill it!!
	pc.Debugf("Stop: killing command: %v\n", pc.cmd.Process.Pid)
	e3 := pc.cmd.Process.Kill()
	pc.Debugf("Stop: killing result: %v\n", e3)

	// Wait for exit
	pc.Debugf("Stop: waiting for command exit: %v\n", pc.cmd.Process.Pid)
	e3 = pc.cmd.Wait()
	pc.Debugf("Stop: wait result: %v\n", e3)

	pc.Tracef("Stop: finished\n")
	return nil
}

func (pc *PluginClient) Config(params map[string]interface{}) error {
	pc.Tracef("Config %s: started\n", pc.plugin)
	params["Name"] = pc.plugin
	_, err := pc.post(pc, "/config", params)
	pc.Tracef("Config %s: finished: %v\n", pc.plugin, err)
	return err
}

func (pc *PluginClient) Publish(e *models.Event) error {
	l := pc.NoPublish()
	l.Tracef("Publish %s: started\n", pc.plugin)
	_, err := pc.post(l.NoPublish(), "/publish", e)
	l.Tracef("Publish %s: finished: %v\n", pc.plugin, err)
	return err
}

func (pc *PluginClient) Action(rt *RequestTracker, a *models.Action) (interface{}, error) {
	pc.Tracef("Action: started\n")
	bytes, err := pc.post(pc, "/action", a)
	var val interface{}
	if err == nil {
		err = json.Unmarshal(bytes, &val)
	}
	pc.Tracef("Action: finished: %v, %v\n", val, err)
	return val, err
}
