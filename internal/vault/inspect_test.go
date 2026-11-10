package vault

import "testing"

func TestInspect(t *testing.T) {
	env := map[string]string{"LONG": "abcdefghijkl", "SHORT": "abc", "EMPTY": ""}
	specs := []Spec{{"LONG", ValueOnly}, {"SHORT", Both}, {"EMPTY", ValueOnly}, {"MISSING", ValueOnly}}
	got := Inspect(specs, func(k string) string { return env[k] })
	want := []VarState{Protected, TooShort, Unset, Unset}
	for i, w := range want {
		if got[i].State != w || got[i].Name != specs[i].Name || got[i].Mode != specs[i].Mode {
			t.Errorf("%s: got %+v, want state %v", specs[i].Name, got[i], w)
		}
	}
	// Inspect and New must agree on how many values are unusable.
	_, st := New(specs, func(k string) string { return env[k] })
	n := 0
	for _, r := range got {
		if r.State != Protected {
			n++
		}
	}
	if n != st.ValuesSkipped {
		t.Errorf("Inspect finds %d unusable, New counts %d", n, st.ValuesSkipped)
	}
}
