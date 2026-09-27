package operationtrust

import (
	"errors"
	"io/fs"
	"sort"
	"testing/fstest"

	"github.com/tplAIter/tplaiter/internal/trustverify"
)

// SnapshotFS materializes only the immutable bytes retained in a verified
// resolution. It never reopens a checkout or preserves a path capability.
func SnapshotFS(runtime *trustverify.Runtime, resolution *trustverify.VerifiedResolution) (fs.FS, error) {
	if runtime == nil || resolution == nil || !resolution.ValidFor(runtime, runtime.Binding()) {
		return nil, errors.New("TRUST_RUNTIME_INVALID")
	}
	snapshot, err := runtime.VerifiedSnapshot(resolution)
	if err != nil || snapshot == nil {
		return nil, errors.New("TRUST_RUNTIME_INVALID")
	}
	entries := snapshot.Entries()
	if !sort.SliceIsSorted(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path }) {
		return nil, errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
	}
	files := make(fstest.MapFS, len(entries))
	for _, entry := range entries {
		if !fs.ValidPath(entry.Path) || entry.Path == "." || (entry.Kind != "file" && entry.Kind != "directory") {
			return nil, errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
		}
		if entry.Kind == "directory" {
			continue
		}
		data, ok := snapshot.Blob(entry.Path)
		if !ok {
			return nil, errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
		}
		if rawDigest(data) != entry.ContentSHA256 {
			return nil, errors.New("TRUST_SOURCE_ADAPTER_UNSUPPORTED")
		}
		files[entry.Path] = &fstest.MapFile{Data: append([]byte(nil), data...), Mode: 0o444}
	}
	return files, nil
}
