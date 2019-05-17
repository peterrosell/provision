package backend

import "testing"

func TestPreferences(t *testing.T) {
	dt := mkDT()
	rt := dt.Request(dt.Logger, "preferences:rw", "bootenvs", "stages", "workflows")
	rt.Do(func(d Stores) {
		if be, err := dt.Pref("defaultBootEnv"); err != nil {
			t.Errorf("Expected to get a defaultBootEnv preference, got nothing")
		} else {
			t.Logf("Got defaultBootEnv %s", be)
		}
		if be, err := dt.Pref("unknownBootEnv"); err == nil && be == "ignore" {
			t.Logf("Got expected value for unknownBootEnv %s", be)
		} else {
			t.Errorf("Got Unexpected error looking for unknownBootEnv: %v, %v", be, err)
		}
		prefs := map[string]string{}
		prefs["unknownBootEnv"] = "ignore"
		if err := dt.SetPrefs(rt, prefs); err != nil {
			t.Errorf("Unexpected error setting prefs: %v", err)
		} else {
			t.Logf("Set unknownBootEnv to ignore")
		}
		prefs["defaultBootEnv"] = "default"
		if err := dt.SetPrefs(rt, prefs); err != nil {
			t.Logf("Expected error setting prefs: %v", err)
		} else {
			t.Errorf("Should have failed setting defaultBootEnv to default")
		}
		prefs["defaultBootEnv"] = "ignore"
		if err := dt.SetPrefs(rt, prefs); err != nil {
			t.Errorf("Unexpected error setting prefs: %v", err)
		} else {
			t.Logf("Set defaultBootEnv to ignore")
		}
		prefs["foo"] = "bar"
		if err := dt.SetPrefs(rt, prefs); err != nil {
			t.Logf("Expected error setting prefs: %v", err)
		} else {
			t.Errorf("Should have failed setting foo to bar")
		}
		prefs["defaultStage"] = "bar"
		if err := dt.SetPrefs(rt, prefs); err != nil {
			t.Logf("Expected error setting prefs: %v", err)
		} else {
			t.Errorf("Should have failed setting defaultStage to bar")
		}
		prefs["baseTokenSecret"] = "lessbytes"
		if err := dt.SetPrefs(rt, prefs); err != nil {
			t.Logf("Expected error setting prefs: %v", err)
		} else {
			t.Errorf("Should have failed setting baseTokenSecret to lessbytes")
		}
		dt.Prefs()
	})
}
