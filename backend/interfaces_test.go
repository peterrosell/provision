package backend

import "testing"

func TestGetInterfaces(t *testing.T) {
	dt := mkDT()

	ifs, err := dt.GetInterfaces()
	if err != nil {
		t.Errorf("GetInterfaces should not err: %v\n", err)
	}
	if len(ifs) == 0 {
		t.Errorf("GetInterfaces should return something: %v\n", ifs)
	}
}
