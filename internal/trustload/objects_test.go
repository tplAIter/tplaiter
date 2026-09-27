package trustload

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tplAIter/tplaiter/internal/trustverify"
)

func TestObjectReaderFixedOriginRawObjects(t *testing.T) {
	root := noFollowTempDir(t)
	origin := "https://example.test/source"
	reader, err := NewObjectReader([]ObjectOrigin{{Origin: origin, RootPath: root}})
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 40)
	if err := os.WriteFile(filepath.Join(root, id), []byte("blob 3\x00abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := reader.ReadObject(context.Background(), trustverify.SourceOrigin(origin), trustverify.ObjectID(id))
	if err != nil || got.Kind != "blob" || string(got.Data) != "abc" {
		t.Fatalf("ReadObject() = %#v, %v", got, err)
	}
	got.Data[0] = 'x'
	again, err := reader.ReadObject(context.Background(), trustverify.SourceOrigin(origin), trustverify.ObjectID(id))
	if err != nil || string(again.Data) != "abc" {
		t.Fatalf("reader aliased object bytes: %#v, %v", again, err)
	}
	if _, err := reader.ReadObject(context.Background(), trustverify.SourceOrigin("https://example.test/other"), trustverify.ObjectID(id)); err == nil {
		t.Fatal("accepted an unregistered origin")
	}
	if _, err := reader.ReadObject(context.Background(), trustverify.SourceOrigin(origin), trustverify.ObjectID(strings.ToUpper(id))); err == nil {
		t.Fatal("accepted uppercase object id")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadObject(context.Background(), trustverify.SourceOrigin(origin), trustverify.ObjectID(id)); err == nil {
		t.Fatal("read after close succeeded")
	}
}

func TestObjectReaderRejectsMalformedRawObjectAndSymlink(t *testing.T) {
	root := noFollowTempDir(t)
	origin := "https://example.test/source"
	reader, err := NewObjectReader([]ObjectOrigin{{Origin: origin, RootPath: root}})
	if err != nil {
		t.Fatal(err)
	}
	for n, raw := range map[string]string{
		strings.Repeat("a", 40): "blob 03\x00abc",
		strings.Repeat("b", 40): "tag 3\x00abc",
		strings.Repeat("c", 40): "blob 2\x00abc",
		strings.Repeat("d", 40): "blob +3\x00abc",
	} {
		if err := os.WriteFile(filepath.Join(root, n), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := reader.ReadObject(context.Background(), trustverify.SourceOrigin(origin), trustverify.ObjectID(n)); err == nil {
			t.Fatalf("accepted malformed raw object %q", raw)
		}
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("blob 3\x00abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := strings.Repeat("e", 40)
	if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadObject(context.Background(), trustverify.SourceOrigin(origin), trustverify.ObjectID(link)); err == nil {
		t.Fatal("accepted symlink object leaf")
	}
}

func TestObjectReaderRetainsOpenedRootAcrossPathReplacement(t *testing.T) {
	root := noFollowTempDir(t)
	origin := "https://example.test/source"
	id := strings.Repeat("f", 40)
	if err := os.WriteFile(filepath.Join(root, id), []byte("blob 3\x00old"), 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := NewObjectReader([]ObjectOrigin{{Origin: origin, RootPath: root}})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	old := root + "-retained"
	if err := os.Rename(root, old); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(old) })
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, id), []byte("blob 3\x00new"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := reader.ReadObject(context.Background(), trustverify.SourceOrigin(origin), trustverify.ObjectID(id))
	if err != nil || string(got.Data) != "old" {
		t.Fatalf("root replacement redirected retained reader: %#v, %v", got, err)
	}
}
