package agent

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/VictorLowther/jsonpatch2"
	"github.com/digitalrebar/provision/api"
	"github.com/digitalrebar/provision/models"
)

// jobLog gets the log for a specific Job and writes it to the passed
// io.Writer
func jobLog(c *api.Client, j *models.Job, dst io.Writer) error {
	return c.Req().UrlFor("jobs", j.Key(), "log").Do(dst)
}

// jobActions returns the expanded list of templates that should be
// written or executed for a specific Job.
func jobActions(c *api.Client, j *models.Job, targetOS string) (models.JobActions, error) {
	res := models.JobActions{}
	req := c.Req().UrlFor("jobs", j.Key(), "actions")
	if targetOS != "" {
		req.Params("os", targetOS)
	}
	return res, req.Do(&res)
}

// runner is responsible for expanding templates and running
// scripts for a single task.
type runner struct {
	// Status codes that may be returned when a script exits.
	failed, incomplete, reboot, poweroff, stop, wantChroot bool
	// Client that the TaskRunner will use to communicate with the API
	c *api.Client
	// The Job that the TaskRunner will log to and update the status of.
	j *models.Job
	// The machine the TaskRunner is running on.
	m *models.Machine
	// The machine's current Task.
	t *models.Task
	// The io.Writer that all logging output goes to.
	// It writes to stderr and to the Job on the server.
	in io.Writer
	// The write side of the pipe that communicates to the servver.
	// Closing this will flush any data left in the pipe.
	pipeWriter                  net.Conn
	agentDir, jobDir, chrootDir string
	logger                      io.Writer
}

// newRunner creates a new TaskRunner for the passed-in machine.
// It creates the matching Job (or resumes the previous incomplete
// one), and handles making sure that all relevant output is written
// to the job log as well as local stderr
func newRunner(c *api.Client, m *models.Machine, agentDir, chrootDir string, logger io.Writer) (*runner, error) {
	if logger == nil {
		logger = ioutil.Discard
	}
	res := &runner{
		c:        c,
		m:        m,
		agentDir: agentDir,
		logger:   logger,
	}
	job := &models.Job{Machine: m.Uuid}
	if err := c.CreateModel(job); err != nil && err != io.EOF {
		return nil, err
	}
	if job.State == "" {
		// Nothing to do.  Not an error
		return nil, nil
	}
	res.j = job
	if strings.HasPrefix(job.Task, "chroot:") {
		res.jobDir = strings.TrimPrefix(job.Task, "chroot:")
		res.wantChroot = true
		return res, nil
	}
	if !strings.Contains(job.Task, ":") {
		t := &models.Task{Name: job.Task}
		if err := c.Req().Fill(t); err != nil {
			return nil, err
		}
		res.t = t
	}
	return res, nil
}

// Close() shuts down the writer side of the logging pipe.
// This will also flush any remaining data to stderr
func (r *runner) Close() {
	if r.pipeWriter != nil {
		r.pipeWriter.Close()
	}
	type flusher interface {
		io.Writer
		Flush() error
	}
	type syncer interface {
		io.Writer
		Sync() error
	}
	switch o := r.logger.(type) {
	case flusher:
		o.Flush()
	case syncer:
		o.Sync()
	}
}

// log writes the string (with a timestamp) to stderr and to the
// server-side log for the current job.
func (r *runner) log(s string, items ...interface{}) {
	fmt.Fprintf(r.in, s+"\n", items...)
}

// expand a writes a file template to the appropriate location.
func (r *runner) expand(action *models.JobAction, taskDir string) error {
	// Write the Contents of this template to the passed Path
	if !strings.HasPrefix(action.Path, "/") {
		action.Path = path.Join(taskDir, path.Clean(action.Path))
	} else if r.chrootDir != "" {
		action.Path = path.Join(r.chrootDir, action.Path)
	}
	r.log("%s: Writing %s to %s", time.Now(), action.Name, action.Path)
	if err := os.MkdirAll(filepath.Dir(action.Path), os.ModePerm); err != nil {
		r.log("Unable to mkdirs for %s: %v", action.Path, err)
		return err
	}
	if err := ioutil.WriteFile(action.Path, []byte(action.Content), 0644); err != nil {
		r.log("Unable to write to %s: %v", action.Path, err)
		return err
	}
	return nil
}

// perform runs a single script action.
func (r *runner) perform(action *models.JobAction, taskDir string) error {
	taskFile := path.Join(taskDir, r.j.Task+"-"+action.Name)
	if err := ioutil.WriteFile(taskFile, []byte(action.Content), 0700); err != nil {
		r.log("Unable to write to script %s: %v", taskFile, err)
		return err
	}

	cmdArray := []string{}
	if interp, ok := action.Meta["Interpreter"]; ok {
		// This is probably usually not required anywhere but Windows,
		// as basically all Unix shell scripts should start with #!,
		// and even on Windows we will try to guess based on the extension.
		cmdArray = append(cmdArray, interp)
	} else if strings.HasSuffix(taskFile, "ps1") {
		cmdArray = append(cmdArray, "powershell.exe")
		cmdArray = append(cmdArray, "-File")
	}
	cmdArray = append(cmdArray, "./"+path.Base(taskFile))
	cmd := exec.Command(cmdArray[0], cmdArray[1:]...)
	cmd.Dir = taskDir
	cmd.Env = append(os.Environ(), "RS_TASK_DIR="+taskDir)
	for _, e := range []string{"RS_UUID", "RS_ENDPOINT", "RS_TOKEN"} {
		if os.Getenv(e) == "" {
			switch e {
			case "RS_UUID":
				cmd.Env = append(cmd.Env, e+"="+r.m.Key())
			case "RS_ENDPOINT":
				cmd.Env = append(cmd.Env, e+"="+r.c.Endpoint())
			case "RS_TOKEN":
				cmd.Env = append(cmd.Env, e+"="+r.c.Token())
			}
		}
	}
	cmd.Stdout = r.in
	cmd.Stderr = r.in
	if err := r.enterChroot(cmd); err != nil {
		r.log("Command failed to set up chroot: %v", err)
		return err
	}
	r.log("Starting command %s\n\n", cmd.Path)
	if err := cmd.Start(); err != nil {
		r.log("Command failed to start: %v", err)
		return err
	}
	// Wait on the process, not the command to exit.
	// We don't want to auto-close stdout and stderr,
	// as we will continue to use them.
	r.log("Command running")
	pState, _ := cmd.Process.Wait()
	r.exitChroot()
	status := pState.Sys().(syscall.WaitStatus)
	sane := r.t.HasFeature("sane-exit-codes")
	if !sane {
		st, err := os.Stat(path.Join(taskDir, ".sane-exit-codes"))
		sane = err == nil && st.Mode().IsRegular()
	}
	code := uint(status.ExitStatus())
	r.log("Command exited with status %d", code)
	if sane {
		switch code {
		case 0:
		case 16:
			r.stop = true
		case 32:
			r.poweroff = true
		case 64:
			r.reboot = true
		case 128:
			r.incomplete = true
		case 144:
			r.stop = true
			r.incomplete = true
		case 160:
			r.incomplete = true
			r.poweroff = true
		case 192:
			r.incomplete = true
			r.reboot = true
		default:
			r.failed = true
		}
	} else {
		switch code {
		case 0:
		case 1:
			r.reboot = true
		case 2:
			r.incomplete = true
		case 3:
			r.incomplete = true
			r.reboot = true
		default:
			r.failed = true
		}
	}
	return nil
}

// run loops over all of the actions for a particular job,
// placing files and executing scripts as appropriate.
// It also arranges for all logging output for the actions
// to go to the right places.
func (r *runner) run() error {
	finalErr := &models.Error{
		Type:  "RUNNER_ERR",
		Model: r.j.Prefix(),
		Key:   r.j.Key(),
	}
	if r.t == nil {
		// no task, return based on the state of the job.
		// These are actions that are handled on the server side
		switch r.j.State {
		case "created", "incomplete":
			finalErr.Errorf("Invalid job state returned: %v", r.j.State)
		case "running":
			finalErr.Errorf("Job %s running somewhere else: %v", r.j.Key(), r.j.State)
		case "failed":
			r.failed = true
		}
		return finalErr.HasError()
	}

	jKey := r.j.Key()
	// Arrange to log everything to the job log and stderr at the same time.
	// Due to how io.Pipe works, this should wind up being fairly synchronous.
	reader, writer := net.Pipe()

	r.in = io.MultiWriter(writer, r.logger)
	r.pipeWriter = writer
	helperWritten := false

	go func() {
		defer reader.Close()
		buf := make([]byte, 1<<16)
		reader.SetReadDeadline(time.Now().Add(1 * time.Second))
		pos := 0
		for {
			count, err := reader.Read(buf[pos:])
			pos += count
			if pos < len(buf) && err == nil {
				continue
			}
			if pos > 0 {
				if r.c.Req().Put(buf[:pos]).UrlFor("jobs", jKey, "log").Do(nil) != nil {
					return
				}
				pos = 0
			}
			if err != nil {
				if os.IsTimeout(err) {
					reader.SetReadDeadline(time.Now().Add(1 * time.Second))
					continue
				}
				return
			}
		}
	}()
	// We are responsible for going from created to running.
	// If this patch fails, we cannot do it
	patch := jsonpatch2.Patch{
		{Op: "test", Path: "/State", Value: r.j.State},
		{Op: "replace", Path: "/State", Value: "running"},
	}
	finalState := "incomplete"
	taskDir, err := ioutil.TempDir(r.agentDir, r.j.Task+"-")
	if err != nil {
		r.log("Failed to create local tmpdir: %v", err)
		finalErr.AddError(err)
		return finalErr
	}
	// No matter how the function exits, we will try to patch the Job
	// to an appropriate final state.
	defer os.RemoveAll(taskDir)
	defer func() {
		if r.failed || r.reboot || r.stop || r.poweroff || r.incomplete {
			newM := models.Clone(r.m).(*models.Machine)
			newM.Runnable = false
			if err := r.c.Req().PatchTo(r.m, newM).Do(&newM); err == nil {
				r.log("Marked machine %s as not runnable", r.m.Name)
				r.m = newM
			} else {
				r.log("Failed to mark machine %s as not runnable: %v", r.m.Name, err)
			}
		}
		exitState := "complete"
		if finalState == "failed" {
			exitState = "failed"
		}
		if r.reboot {
			exitState = "reboot"
		} else if r.poweroff {
			exitState = "poweroff"
		} else if r.stop {
			exitState = "stop"
		}
		finalPatch := jsonpatch2.Patch{
			{Op: "test", Path: "/State", Value: "running"},
			{Op: "replace", Path: "/State", Value: finalState},
			{Op: "replace", Path: "/ExitState", Value: exitState},
		}
		if err := r.c.Req().Patch(finalPatch).UrlForM(r.j).Do(&r.j); err != nil {
			r.log("Failed to update job %s:%s:%s to its final state %s", r.j.Workflow, r.j.Stage, r.j.Task, finalState)
		} else {
			r.log("Updated job for %s:%s:%s to %s", r.j.Workflow, r.j.Stage, r.j.Task, finalState)
		}
	}()
	obj, err := r.c.PatchModel(r.j.Prefix(), r.j.Key(), patch)
	if err != nil {
		finalErr.AddError(err)
		return finalErr
	}
	r.j = obj.(*models.Job)
	r.log("Starting task %s:%s:%s on %s", r.j.Workflow, r.j.Stage, r.j.Task, r.m.Name)
	// At this point, we are running.
	var actions models.JobActions
	if allActions, err := jobActions(r.c, r.j, runtime.GOOS); err != nil {
		r.log("Failed to render actions: %v", err)
		finalErr.AddError(err)
		return finalErr
	} else {
		actions = allActions.FilterOS(runtime.GOOS)
	}
	for i, action := range actions {
		final := len(actions)-1 == i
		r.failed = false
		r.incomplete = false
		r.poweroff = false
		r.reboot = false
		r.stop = false
		var err error
		if action.Path != "" {
			err = r.expand(action, taskDir)
		} else {
			if !helperWritten {
				err = ioutil.WriteFile(path.Join(taskDir, "helper"), cmdHelper, 0600)
				if err != nil {
					finalErr.AddError(err)
					return finalErr
				}
				helperWritten = true
			}
			err = r.perform(action, taskDir)
			// Contents is a script to run, run it.
		}
		if err != nil {
			r.failed = true
			finalState = "failed"
			finalErr.AddError(err)
			r.log("Task %s %s", r.j.Task, finalState)
			return finalErr
		}
		r.log("Action %s finished", action.Name)
		// If a non-final action sets the incomplete flag, it actually
		// means early success and stop processing actions for this task.
		// This allows actions to be structured in an "early exit"
		// fashion.
		//
		// Only the final action can actually set things as incomplete.
		if !final && r.incomplete {
			r.incomplete = !r.incomplete
			break
		}
		if r.failed {
			finalState = "failed"
			break
		}
		if r.reboot || r.poweroff || r.stop {
			r.incomplete = !final
			break
		}
	}
	if !r.failed && !r.incomplete {
		finalState = "finished"
	}
	r.log("Task %s %s", r.j.Task, finalState)
	return nil
}
