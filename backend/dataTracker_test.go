package backend

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/digitalrebar/logger"
	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/store"
)

var (
	backingStore store.Store
	tmpDir       string
)

type crudTest struct {
	name string
	op   func(models.Model) (bool, error)
	t    models.Model
	pass bool
}

func (test crudTest) Test(t *testing.T, rt *RequestTracker) {
	t.Helper()
	var passed bool
	var err error
	rt.Do(func(d Stores) {
		passed, err = test.op(test.t)
	})
	msg := fmt.Sprintf("%s: wanted to pass: %v, passed: %v", test.name, test.pass, passed)
	if passed == test.pass {
		t.Log(msg)
		if !test.pass {
			t.Logf("   err: %#v", err)
		}
	} else {
		t.Errorf("ERROR: %s, ", msg)
		t.Errorf("   err: %#v", err)
		t.Errorf("   obj: %#v", test.t)
	}
}

func loadExample(rt *RequestTracker, kind, p string) (ok bool, err error) {
	buf, err := os.Open(p)
	if err != nil {
		return false, err
	}
	defer buf.Close()
	res, err := models.New(kind)
	if err != nil {
		log.Panicf("Unknown models %s: %v", kind, err)
	}

	dec := json.NewDecoder(buf)
	if err := dec.Decode(&res); err != nil {
		return false, err
	}
	rt.Do(func(d Stores) {
		ok, err = rt.Create(res)
	})
	return
}

func mkDT() *DataTracker {
	baseLog := log.New(os.Stdout, "dt", 0)
	l := logger.New(baseLog).Log("backend")
	ss, _ := store.Open("memory:///")
	s, err := DefaultDataStack("", "memory:///", "", "", "", tmpDir, l, nil)
	if err != nil {
		panic("Cannot happen")
	}
	dt := NewDataTracker(s,
		ss,
		tmpDir,
		tmpDir,
		"127.0.0.1",
		false,
		8091,
		8092,
		"fred",
		l,
		map[string]string{"systemGrantorSecret": "itisfred", "defaultStage": "none", "defaultBootEnv": "local", "unknownBootEnv": "ignore"},
		NewPublishers(baseLog),
		nil)
	return dt
}

func TestMain(m *testing.M) {
	var err error
	tmpDir, err = ioutil.TempDir("", "datatracker-")
	if err != nil {
		log.Printf("Creating temp dir for file root failed: %v", err)
		os.Exit(1)
	}
	ret := m.Run()
	err = os.RemoveAll(tmpDir)
	if err != nil {
		log.Printf("Creating temp dir for file root failed: %v", err)
		os.Exit(1)
	}
	os.Exit(ret)
}
