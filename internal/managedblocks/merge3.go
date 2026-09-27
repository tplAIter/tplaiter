package managedblocks

import "bytes"

// Merge3 preserves either independent side when the other equals base. A
// concurrent edit yields deterministic LF conflict bytes for existing callers.
func Merge3(base, ours, theirs []byte) ([]byte, bool) {
	return Merge3WithEOL(base, ours, theirs, []byte("\n"))
}

// Merge3WithEOL is the layout-aware form used by reconciliation.
func Merge3WithEOL(base, ours, theirs, eol []byte) ([]byte, bool) {
	if bytes.Equal(ours, base) {
		return append([]byte(nil), theirs...), false
	}
	if bytes.Equal(theirs, base) || bytes.Equal(ours, theirs) {
		return append([]byte(nil), ours...), false
	}
	out := append([]byte("<<<<<<< ours"), eol...)
	out = append(out, ours...)
	out = append(out, []byte("=======")...)
	out = append(out, eol...)
	out = append(out, theirs...)
	out = append(out, []byte(">>>>>>> template")...)
	out = append(out, eol...)
	return out, true
}
