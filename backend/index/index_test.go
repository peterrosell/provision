package index

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/digitalrebar/provision/models"
	"github.com/digitalrebar/store"
)

type testThing int64

func (t testThing) Key() string {
	return fmt.Sprintf("%04d", int64(t))
}

func (t testThing) KeyName() string {
	return fmt.Sprintf("%04d", int64(t))
}

func (t testThing) Prefix() string {
	return "integers"
}

func (t testThing) New() models.Model {
	return t
}

func (t testThing) Backend() store.Store {
	return nil
}

func (t testThing) Indexes() map[string]Maker {
	return map[string]Maker{
		"Base": Make(
			true,
			"string",
			func(i, j models.Model) bool {
				return i.(testThing) < j.(testThing)
			},
			func(ref models.Model) (gte, gt Test) {
				return func(s models.Model) bool {
						return s.(testThing) >= ref.(testThing)
					},
					func(s models.Model) bool {
						return s.(testThing) > ref.(testThing)
					}
			},
			func(s string) (models.Model, error) {
				res, err := strconv.ParseInt(s, 10, 64)
				return testThing(res), err
			}),
		"Odd": MakeUnordered("odd",
			func(i, j models.Model) bool {
				return i.(testThing)&1 == j.(testThing)&1
			},
			func(s string) (models.Model, error) {
				res, err := strconv.ParseInt(s, 10, 64)
				return testThing(res), err
			}),
	}
}

func matchIdx(t *testing.T, i *Index, ints ...int64) {
	if len(i.objs) != len(ints) {
		t.Errorf("Expected %d items, got %d", len(ints), len(i.objs))
	}
	for j := range ints {
		if int64(i.objs[j].(testThing)) != ints[j] {
			t.Errorf("At position %d, expected %d, got %d", j, ints[j], i.objs[j])
		}
	}
}

func TestAddIndex(t *testing.T) {
	objs := make([]models.Model, 10)
	objs[0] = testThing(10)
	objs[1] = testThing(4)
	objs[2] = testThing(14)
	objs[3] = testThing(0)
	objs[4] = testThing(18)
	objs[5] = testThing(2)
	objs[6] = testThing(12)
	objs[7] = testThing(16)
	objs[8] = testThing(6)
	objs[9] = testThing(8)
	idx := Create([]models.Model{})
	idx.Add(objs...)
	for i, item := range idx.Items() {
		if (int64(i) * 2) != int64(item.(testThing)) {
			t.Errorf("Expected %d, got %d", i, item)
		}
	}
	objs = make([]models.Model, 11)
	objs[0] = testThing(11)
	objs[1] = testThing(5)
	objs[2] = testThing(15)
	objs[3] = testThing(1)
	objs[4] = testThing(19)
	objs[5] = testThing(3)
	objs[6] = testThing(13)
	objs[7] = testThing(17)
	objs[8] = testThing(7)
	objs[9] = testThing(9)
	objs[10] = testThing(8)
	idx.Add(objs...)
	for i, item := range idx.Items() {
		if int64(i) != int64(item.(testThing)) {
			t.Errorf("Expected %d, got %d", i, item)
		}
	}
}

func TestIndexes(t *testing.T) {
	objs := make([]models.Model, 100)
	for i := range objs {
		objs[i] = testThing(len(objs) - i)
	}
	idx := New(objs)
	lim, err := Limit(10)(idx)
	if err != nil {
		t.Errorf("Limit returned an unexpected error: %v", err)
	}
	if len(lim.objs) != 10 {
		t.Errorf("Limit failed to limit returned 10 items, returned %d", len(lim.objs))
	} else {
		t.Logf("Limit returned 10 items")
	}
	offs, err := Offset(5)(lim)
	if err != nil {
		t.Errorf("Offset returned an unexpected error: %v", err)
	}
	if len(offs.objs) != 5 {
		t.Errorf("Offset failed to return 5 items, returned %d", len(offs.objs))
	} else {
		t.Logf("Offset returned 5 items")
	}
	indexes := testThing(0).Indexes()
	offs, err = Sort(indexes["Base"])(offs)
	if err != nil {
		t.Errorf("Sort returned an unexpected error: %v", err)
	}
	matchIdx(t, offs, 91, 92, 93, 94, 95)
	idx, err = All(Reverse(), Reverse())(idx)
	if err != nil {
		t.Errorf("Reverse returned an unexpected error: %v", err)
	}
	lim, err = Limit(10)(idx)
	if err != nil {
		t.Errorf("Unexpected error taking the limit: %v", err)
	}
	matchIdx(t, lim, 100, 99, 98, 97, 96, 95, 94, 93, 92, 91)
	idx, err = Sort(indexes["Base"])(idx)
	if err != nil {
		t.Errorf("Unexpected error sorting base: %v", err)
	}
	lim, err = Limit(10)(idx)
	if err != nil {
		t.Errorf("Unexpected error taking the limit: %v", err)
	}
	matchIdx(t, lim, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
	tween, err := Between("5", "10")(idx)
	if err != nil {
		t.Errorf("Unexpected error processing Between: %v", err)
	}
	matchIdx(t, tween, 5, 6, 7, 8, 9, 10)
	_, err = Limit(-1)(tween)
	if err == nil {
		t.Errorf("Limit should have thrown an error with a negative limit")
	} else {
		t.Logf("Got expected error taking negative limit: %v", err)
	}
	matchIdx(t, tween, 5, 6, 7, 8, 9, 10)
	_, err = Offset(-1)(tween)
	if err == nil {
		t.Errorf("Offset should have thrown an error with a negative offset")
	} else {
		t.Logf("Got expected error taking negative offset: %v", err)
	}
	matchIdx(t, tween, 5, 6, 7, 8, 9, 10)
	lim, err = Limit(10)(tween)
	if err != nil {
		t.Errorf("Got unexpected error taking limit: %v", err)
	}
	matchIdx(t, lim, 5, 6, 7, 8, 9, 10)
	offs, err = Offset(10)(tween)
	if err != nil {
		t.Errorf("Got unexpected error taking limit: %v", err)
	}
	matchIdx(t, offs)
	tween, err = Except("6", "9")(tween)
	if err != nil {
		t.Errorf("Got unexpected error taking except: %v", err)
	}
	matchIdx(t, tween, 5, 10)
	lt, err := Lt("6")(idx)
	if err != nil {
		t.Errorf("Got unexpected error running Lt: %v", err)
	}
	matchIdx(t, lt, 1, 2, 3, 4, 5)
	lt, err = Lte("6")(idx)
	if err != nil {
		t.Errorf("Got unexpected error running Lte: %v", err)
	}
	matchIdx(t, lt, 1, 2, 3, 4, 5, 6)
	lt, err = Eq("6")(idx)
	if err != nil {
		t.Errorf("Got unexpected error running Eq: %v", err)
	}
	matchIdx(t, lt, 6)
	lt, err = Gte("95")(idx)
	if err != nil {
		t.Errorf("Got unexpected error running Gte: %v", err)
	}
	matchIdx(t, lt, 95, 96, 97, 98, 99, 100)
	lt, err = Gt("95")(idx)
	if err != nil {
		t.Errorf("Got unexpected error running Gt: %v", err)
	}
	matchIdx(t, lt, 96, 97, 98, 99, 100)
	lt, err = Ne("98")(lt)
	if err != nil {
		t.Errorf("Got unexpected error running Ne: %v", err)
	}
	matchIdx(t, lt, 96, 97, 99, 100)
	lt, err = Select(func(s models.Model) bool { return s.(testThing)%2 == 0 })(lt)
	if err != nil {
		t.Errorf("Got unexpected error running Select: %v", err)
	}
	matchIdx(t, lt, 96, 100)
	ref, err := idx.Fill("6")
	if err != nil {
		t.Errorf("Unexpected error creating reference testThing from `6`")
	}
	lower, upper := idx.Tests(ref)
	sub, err := Subset(lower, upper)(idx)
	if err != nil {
		t.Errorf("Got unexpected error running Subset: %v", err)
	}
	matchIdx(t, sub, 6)
}

func TestOddIndexes(t *testing.T) {
	objs := make([]models.Model, 10)
	for i := range objs {
		objs[i] = testThing(len(objs) - i)
	}
	idx := New(objs)
	odds, err := Use(testThing(0).Indexes()["Odd"])(idx)
	if err != nil {
		t.Errorf("Unexpected error creating odds index from a list of number")
	}
	someOdds, err := Eq("1")(odds)
	if err != nil {
		t.Errorf("Error extracting 5 odd numbers from odds")
	}
	matchIdx(t, someOdds, 9, 7, 5, 3, 1)
	someEvens, err := Eq("0")(odds)
	if err != nil {
		t.Errorf("Error extracting 5 even numbers from odds")
	}
	matchIdx(t, someEvens, 10, 8, 6, 4, 2)
	someOdds, err = Ne("1")(odds)
	if err != nil {
		t.Errorf("Error extracting 5 not-odd numbers from odds")
	}
	matchIdx(t, someOdds, 10, 8, 6, 4, 2)
	someEvens, err = Ne("0")(odds)
	if err != nil {
		t.Errorf("Error extracting 5 not-even numbers from odds")
	}
	matchIdx(t, someEvens, 9, 7, 5, 3, 1)
}
