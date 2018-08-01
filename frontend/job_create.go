package frontend

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/models"
	"github.com/pborman/uuid"
)

func saveMachineAndNoJob(rt *backend.RequestTracker, m *backend.Machine) (int, error) {
	if _, err := rt.Update(m); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusNoContent, nil
}

// This function is sort of hairy, and I do not apoligize for it.
func realCreateJob(rt *backend.RequestTracker, b *backend.Job) (int, error) {
	mo := rt.Find("machines", b.Machine.String())
	if mo == nil {
		// We cannot create jobs for nonexistent machines.
		err := &models.Error{
			Code:     http.StatusUnprocessableEntity,
			Type:     backend.ValidationError,
			Messages: []string{fmt.Sprintf("Machine %s does not exist", b.Machine.String())},
		}
		return err.Code, err
	}
	oldM := backend.AsMachine(mo)
	if !(oldM.Runnable && oldM.Available) {
		// Machine isn't runnable, return a conflict.
		err := &models.Error{
			Code:     http.StatusConflict,
			Type:     "Conflict",
			Messages: []string{fmt.Sprintf("Machine %s is not runnable", b.Machine.String())},
		}
		return err.Code, err
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
	}
	if m.CurrentTask >= len(m.Tasks) {
		// Nothing to do here.
		return http.StatusNoContent, nil
	}
	// Figure out what task to run next.  This is almost always the same as the current
	// task
	taskToRun := m.CurrentTask
	if taskToRun == -1 {
		// Someone reset the task list, and we are not in workflow mode.
		taskToRun = 0
	}
	if cj.CurrentIndex != m.CurrentTask &&
		!(cj.State == "complete" || cj.State == "failed") {
		rt.Infof("Machine %s Task list has been reset to %d, failing current job %s",
			cj.Machine.String(),
			m.CurrentTask,
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
			return http.StatusAccepted, nil
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
			err := &models.Error{
				Code:     http.StatusConflict,
				Type:     "Conflict",
				Messages: []string{fmt.Sprintf("Machine %s already has running or created job", b.Machine.String())},
			}
			return err.Code, err
		}
	}
	// Exit early if we finished all our tasks
	if taskToRun >= len(m.Tasks) {
		m.CurrentTask = len(m.Tasks)
		return saveMachineAndNoJob(rt, m)
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
		if _, err := rt.Create(nb); err != nil {
			return http.StatusInternalServerError, err
		}
		nb.Log(rt, bytes.NewBufferString(logMsg))
		cj = nb
	}
	m.CurrentTask = taskToRun
	if m.BootEnv != oldM.BootEnv || m.Stage != oldM.Stage {
		// If the stage or bootenv changed, we need to return without creating
		// a job to allow the runner to handle any required reboots.
		if oldM.Stage != m.Stage {
			m.Params["change-stage/map"] = map[string]string{oldM.Stage: m.Stage}
		}
		return saveMachineAndNoJob(rt, m)
	}
	if m.CurrentTask >= len(m.Tasks) {
		// Nothing to do, hooray!
		return saveMachineAndNoJob(rt, m)
	}
	// Create our shiny new task.
	thisTask := m.Tasks[m.CurrentTask]
	b.StartTime = time.Now()
	b.Previous = cj.Uuid
	b.Machine = m.Uuid
	b.Stage = m.Stage
	b.BootEnv = m.BootEnv
	b.Workflow = m.Workflow
	b.CurrentIndex = m.CurrentTask
	b.NextIndex = m.CurrentTask + 1
	b.Task = thisTask
	b.State = "created"
	if _, err := rt.Create(b); err != nil {
		return http.StatusInternalServerError, err
	}
	m.CurrentJob = b.Uuid
	rt.Infof("Created job %s for task %s at index %d", b.UUID(), b.Task, b.CurrentIndex)
	if _, err := rt.Update(m); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusCreated, nil
}
