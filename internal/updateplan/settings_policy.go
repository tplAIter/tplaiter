package updateplan

import (
	"bytes"
	"unicode/utf8"
)

const settingsTextMarkers = "settings-owned-text-conflict-markers"

// This is a private deterministic decision, not a caller-controlled allow flag.
// Every publication receives a freshly reconstructed opaque plan; cold material
// authentication reconstructs the same choices/warnings/bytes and fingerprint.
func settingsConflictPublication(in Input, c Change) bool {
	return len(in.SettingsPairs) > 0 && c.Conflict && c.Decision == settingsTextMarkers && c.Operation == "write"
}

func settingsMergeableText(parts ...[]byte) bool {
	for _, p := range parts {
		if !utf8.Valid(p) || bytes.Contains(p, []byte{0}) || bytes.Count(p, []byte("\n")) > 2047 {
			return false
		}
	}
	return true
}

func settingsDecisions(changes []Change, observed *observation, base, target map[string][]byte) []Change {
	for i := range changes {
		c := &changes[i]
		old, owned := base[c.Path]
		next, wanted := target[c.Path]
		work := observed.files[c.Path]
		if !owned {
			continue
		}
		if c.Before != nil && c.Before.Mode != 0o644 {
			c.Conflict = true
			c.Reason = "permission change preserved"
			continue
		}
		if !wanted && c.Reason == "local changes preserved" {
			if !settingsMergeableText(old, work) {
				c.Conflict = true
				c.Reason = "unsafe non-text conditional removal preserved"
				continue
			}
			c.Decision = "settings-retained-local-removal"
			c.Warning = c.Path + " retained because it contains local edits"
			continue
		}
		if c.Reason != "three-way merge" || !wanted {
			continue
		}
		if !settingsMergeableText(old, work, next) {
			c.Conflict = true
			c.Reason = "unsafe non-text merge preserved"
			continue
		}
		merged, conflict := settingsMergeText(old, work, next)
		*c = decision(observed, c.Path, merged, true, "three-way merge", conflict)
		if conflict {
			c.Decision = settingsTextMarkers
			c.Reason = "owned text conflict markers require resolution"
		}
	}
	return changes
}
