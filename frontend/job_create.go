package frontend

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/models"
	"github.com/pborman/uuid"
)

func makeDeferredAction(f *Frontend,
	rt *backend.RequestTracker,
	action *models.Action,
	prefix, key, jobKey string) func(*models.Error) *backend.Job {
	return func(ret *models.Error) *backend.Job {
		buf := &bytes.Buffer{}
		ret.Code = http.StatusAccepted
		res, err := f.pc.Actions.Run(rt, prefix, action)
		if res != nil {
			fmt.Fprintf(buf, "Results from plugin invoke:\n")
			enc := json.NewEncoder(buf)
			enc.SetIndent("", "  ")
			enc.Encode(res)
			fmt.Fprintf(buf, "\nEnd of results\n")
		}
		if err == nil {
			rt.Publish(prefix, action.Command, key, action)
		} else {
			fmt.Fprintf(buf, "Action invoke %s failed\n%v", action.Command, err)
			ret.Errorf("Action invoke %s failed", action.Command)
			ret.AddError(err)
		}
		var job *backend.Job
		rt.Do(func(_ backend.Stores) {
			var machine *backend.Machine
			if obj := rt.Find("machines", key); obj != nil {
				machine = backend.AsMachine(obj)
			} else {
				ret.Errorf("Machine %s vanished, will not be able to update it.", key)
			}
			if obj := rt.Find("jobs", jobKey); obj != nil {
				job = backend.AsJob(obj)
			} else {
				ret.Errorf("Job %s vanished, cannot log against it", jobKey)
				return
			}
			if ret.ContainsError() {
				job.State = "failed"
				job.ExitState = "failed"
				job.EndTime = time.Now()
				if machine != nil {
					machine.Runnable = false
					rt.Update(machine)
				}
			} else {
				job.State = "finished"
				job.ExitState = "complete"
				job.EndTime = time.Now()
			}
			job.Log(rt, buf)
			if _, err := rt.Update(job); err != nil {
				ret.AddError(err)
			}
		})
		if ret.ContainsError() {
			ret.Code = http.StatusInternalServerError
		} else {
			ret.Code = http.StatusAccepted
		}
		return job
	}
}

func handleAction(f *Frontend,
	rt *backend.RequestTracker,
	m *backend.Machine,
	pa string,
	ct int,
	ret *models.Error) func(*models.Error) *backend.Job {
	ret = &models.Error{
		Code: http.StatusUnprocessableEntity,
		Type: backend.ValidationError,
	}
	action := &models.Action{
		Model:  m,
		Params: map[string]interface{}{},
	}
	if pparts := strings.SplitN(pa, ":", 2); len(pparts) == 2 {
		action.Plugin = pparts[0]
		action.Command = pparts[1]
	} else {
		action.Command = pa
	}
	// the event.
	nb := backend.ModelToBackend(&models.Job{}).(*backend.Job)
	nb.Fill()
	nb.Uuid = uuid.NewRandom()
	nb.StartTime = time.Now()
	nb.Previous = m.CurrentJob
	nb.Machine = m.Uuid
	nb.Stage = m.Stage
	nb.BootEnv = m.BootEnv
	nb.Workflow = m.Workflow
	nb.CurrentIndex = ct
	nb.NextIndex = ct + 1
	nb.Task = m.Tasks[ct]
	nb.State = "running"
	if nb.Previous == nil || len(nb.Previous) == 0 {
		nb.Previous = uuid.Parse("00000000-0000-0000-0000-000000000000")
	}
	if _, err := rt.Create(nb); err != nil {
		ret.Code = http.StatusInternalServerError
		ret.AddError(err)
		return nil
	}
	m.CurrentJob = nb.Uuid
	m.CurrentTask = ct
	if _, err := rt.Update(m); err != nil {
		ret.Code = http.StatusInternalServerError
		ret.AddError(err)
		nb.State = "failed"
		rt.Remove(nb)
		return nil
	}
	validAction, err := validateAction(f, rt, m.Prefix(), m.Key(), action)
	if err.ContainsError() {
		ret.AddError(err)
		nb.State = "failed"
		buf := &bytes.Buffer{}
		fmt.Fprintf(buf, "Action %s validation failed:\n%v", pa, err)
		nb.Log(rt, buf)
		rt.Update(nb)
		m.Runnable = false
		rt.Update(m)
		return nil
	}

	return makeDeferredAction(f, rt, validAction, m.Prefix(), m.Key(), nb.Key())
}

func saveMachineAndNoJob(rt *backend.RequestTracker, m *backend.Machine, ret *models.Error) {
	if _, err := rt.Update(m); err != nil {
		ret.Code = http.StatusInternalServerError
		ret.AddError(err)
	} else {
		ret.Code = http.StatusNoContent
	}
}

func saveMachineAndCreateJob(rt *backend.RequestTracker, m *backend.Machine, b *backend.Job, ret *models.Error) {
	if _, err := rt.Create(b); err != nil {
		ret.Code = http.StatusInternalServerError
		ret.AddError(err)
		return
	}
	m.CurrentJob = b.Uuid
	rt.Infof("Created job %s for task %s at index %d", b.UUID(), b.Task, b.CurrentIndex)
	if _, err := rt.Update(m); err != nil {
		ret.Code = http.StatusInternalServerError
		ret.AddError(err)
		return
	}
	ret.Code = http.StatusCreated
}

// This function is sort of hairy, and I do not apoligize for it.
func realCreateJob(f *Frontend,
	rt *backend.RequestTracker,
	b *backend.Job,
	err *models.Error) (*backend.Job, func(*models.Error) *backend.Job) {
	var mo models.Model
	mo = rt.Find("machines", b.Machine.String())
	if mo == nil {
		// We cannot create jobs for nonexistent machines.
		err.Code = http.StatusUnprocessableEntity
		err.Type = backend.ValidationError
		err.Messages = []string{fmt.Sprintf("Machine %s does not exist", b.Machine.String())}
		return nil, nil
	}
	oldM := backend.AsMachine(mo)
	if !(oldM.Runnable && oldM.Available) {
		// Machine isn't runnable, return a conflict.
		err.Code = http.StatusConflict
		err.Type = "Conflict"
		err.Messages = []string{fmt.Sprintf("Machine %s is not runnable", b.Machine.String())}
		return nil, nil
	}
	// Clone oldM, because we will need to update the machine at some point
	// in this process, and we do not want to do so prematurely.
	m := backend.ModelToBackend(models.Clone(oldM)).(*backend.Machine)
	m.InRunner()
	var cj *backend.Job
	// Are we running a job or not on list yet, do some checking.
	if jo := rt.Find("jobs", m.CurrentJob.String()); jo != nil {
		// Our current job still exists.
		cj = jo.(*backend.Job)
	} else {
		// make the current job record refer to a job that does not
		// exist, and which has failed.
		cj = backend.ModelToBackend(&models.Job{}).(*backend.Job)
		cj.Uuid = uuid.Parse("00000000-0000-0000-0000-000000000000")
		cj.State = "failed"
		if m.CurrentJob != nil && len(m.CurrentJob) > 0 {
			// Someone deleted the Job record for our current job.  Fake it instead.
			cj.Uuid = m.CurrentJob
		}
		rt.Infof("Machine %s Current Job %s couldn't be found. Using fake failed job.",
			cj.Machine.String(),
			cj.Uuid.String())
	}
	if m.CurrentTask >= len(m.Tasks) {
		// Nothing to do here.
		return nil, nil
	}
	// Figure out what task to run next.  This is almost always the same as the current
	// task
	taskToRun := m.CurrentTask
	if cj.CurrentIndex != m.CurrentTask &&
		!(cj.State == "finished" || cj.State == "failed") {
		rt.Infof("Machine %s Task list has been reset to %d from %d, failing current job %s",
			cj.Machine.String(),
			m.CurrentTask,
			cj.CurrentIndex,
			cj.Uuid.String())
		cj.State = "failed"
		cj.ExitState = "failed"
		rt.Update(cj)
	} else {
		rt.Infof("Machine %s is evaluating task list at %d", b.Machine.String(), m.CurrentTask)
		switch cj.State {
		case "incomplete":
			rt.Infof("Machine %s task %s at %d is incomplete, rerunning it",
				cj.Machine.String(), cj.Task, m.CurrentTask)
			*b = *cj
			err.Code = http.StatusAccepted
			return cj, nil
		case "finished":
			// Advance to the next task
			rt.Infof("Machine %s task %s at %d is finished, advancing to %d",
				cj.Machine.String(), cj.Task, m.CurrentTask, taskToRun)
			taskToRun++
		case "failed":
			rt.Infof("Machine %s task %s at %d is failed, retrying",
				cj.Machine.String(), cj.Task, m.CurrentTask)
		default:
			rt.Warnf("Machine %s task %s at %d is %s, conflict",
				cj.Machine.String(), cj.Task, m.CurrentTask, cj.State)
			// Need to error - running job already running or just created.
			err.Code = http.StatusConflict
			err.Type = "Conflict"
			err.Messages = []string{fmt.Sprintf("Machine %s already has running or created job", b.Machine.String())}
			return nil, nil
		}
	}
	if taskToRun == -1 {
		// Someone reset the task list, and we are not in workflow mode.
		taskToRun = 0
	}
	// Exit early if we finished all our tasks
	if taskToRun >= len(m.Tasks) {
		m.CurrentTask = len(m.Tasks)
		saveMachineAndNoJob(rt, m, err)
		return nil, nil
	}
	// Check for stage and bootenv changes.
	// These generate fake server side job logs as needed, and any stage or bootenv changes
	// are gathered to be committed all at once.
	for ; taskToRun < len(m.Tasks) && strings.Contains(m.Tasks[taskToRun], ":"); taskToRun++ {
		rt.Infof("Machine %s ([%d]%s)is checking to see if it needs to change stage",
			b.Machine.String(),
			taskToRun,
			m.Tasks[taskToRun])
		st := strings.SplitN(m.Tasks[taskToRun], ":", 2)
		logMsg := ""
		// Handle bootenv and stage changes if needed, If no changes are
		// needed, we do not generate log events.  This can happen when
		// resetting the stage and/or bootenv does not result in an actual
		// change to the machine because it is already in the target stage
		// or bootenv.
		switch st[0] {
		case "chroot":
			logMsg = fmt.Sprintf("Machine %s agent is being signalled to chroot to %s and continue",
				b.Machine.String(), st[1])
		case "stage":
			if m.Stage == st[1] {
				continue
			}
			logMsg = fmt.Sprintf("Machine %s changing from stage %s to %s", b.Machine.String(), m.Stage, st[1])
			m.Stage = st[1]
		case "bootenv":
			if m.BootEnv == st[1] {
				continue
			}
			logMsg = fmt.Sprintf("Machine %s changing from bootenv %s to %s", b.Machine.String(), m.BootEnv, st[1])
			m.BootEnv = st[1]
		case "action":
			return nil, handleAction(f, rt, m, st[1], taskToRun, err)
		}
		// We actually need to generate a stage/bootenv change. Create a fake job to track
		// the event.
		nb := backend.ModelToBackend(&models.Job{}).(*backend.Job)
		nb.Fill()
		nb.Uuid = uuid.NewRandom()
		nb.StartTime = time.Now()
		nb.Previous = cj.Uuid
		nb.Machine = m.Uuid
		nb.Stage = m.Stage
		nb.BootEnv = m.BootEnv
		nb.Workflow = m.Workflow
		nb.CurrentIndex = taskToRun
		nb.NextIndex = taskToRun + 1
		nb.Task = m.Tasks[taskToRun]
		nb.State = "finished"
		nb.ExitState = "complete"
		nb.EndTime = time.Now()
		if _, cerr := rt.Create(nb); cerr != nil {
			err.Code = http.StatusInternalServerError
			err.AddError(err)
			return nil, nil
		}
		nb.Log(rt, bytes.NewBufferString(logMsg))
		cj = nb
		m.CurrentJob = nb.Uuid
		break
	}
	m.CurrentTask = taskToRun
	if m.BootEnv != oldM.BootEnv || m.Stage != oldM.Stage {
		// If the stage or bootenv changed, we need to return without creating
		// a job to allow the runner to handle any required reboots.
		if oldM.Stage != m.Stage {
			m.Params["change-stage/map"] = map[string]string{oldM.Stage: m.Stage}
		}
		saveMachineAndNoJob(rt, m, err)
		return cj, nil
	}
	if m.CurrentTask >= len(m.Tasks) {
		// Nothing to do, hooray!
		saveMachineAndNoJob(rt, m, err)
		return cj, nil
	}
	// Create our shiny new task.
	b.StartTime = time.Now()
	b.Previous = cj.Uuid
	b.Machine = m.Uuid
	b.Stage = m.Stage
	b.BootEnv = m.BootEnv
	b.Workflow = m.Workflow
	b.CurrentIndex = m.CurrentTask
	b.NextIndex = m.CurrentTask + 1
	b.Task = m.Tasks[m.CurrentTask]
	b.State = "created"
	saveMachineAndCreateJob(rt, m, b, err)
	return b, nil
}
