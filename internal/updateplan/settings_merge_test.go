package updateplan

import (
	"bytes"
	"testing"
)

func TestNativeSettingsTextMergePolicy(t *testing.T) {
	for _, tc := range []struct {
		base, ours, theirs, want string
		conflict                 bool
	}{
		{"a\nb\nc\n", "a\ninsert\nb\nc\n", "a\nb\nC\n", "a\ninsert\nb\nC\n", false},
		{"a\nb\nc\n", "a\nMINE\nc\n", "a\nbeta\nc\n", "a\n<<<<<<< ours\nMINE\n=======\nbeta\n>>>>>>> template\nc\n", true},
	} {
		got, conflict := settingsMergeText([]byte(tc.base), []byte(tc.ours), []byte(tc.theirs))
		if string(got) != tc.want || conflict != tc.conflict {
			t.Fatalf("merge: %q conflict=%v", got, conflict)
		}
	}
	if settingsMergeableText([]byte("nul\x00")) || settingsMergeableText([]byte{0xff}) || settingsMergeableText(bytes.Repeat([]byte("\n"), 2048)) {
		t.Fatal("unsafe text admitted")
	}
}
