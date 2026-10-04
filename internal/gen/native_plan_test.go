package gen

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/tplAIter/tplaiter/internal/manifest"
	"github.com/tplAIter/tplaiter/internal/ownership"
	"github.com/tplAIter/tplaiter/internal/settings"
)

// Pure parser tests use ordinary untrusted inputs; they never mint a runtime
// capability and must not be interpreted as signed generator delivery evidence.
func TestNativePureParametersAnchorsAndBatchPreflight(t *testing.T) {
	tpl := &manifest.Template{Generators: []manifest.Generator{{Kind: "entity", Snippet: "entity.tmpl", Target: "internal/{{ .Name.Snake }}.go", Params: []manifest.Param{{Name: "fields", Type: manifest.ParamTypeFields, Required: true}, {Name: "count", Type: manifest.ParamTypeInt, Default: 2}, {Name: "enabled", Type: manifest.ParamTypeBool, Default: true}, {Name: "tags", Type: manifest.ParamTypeList}, {Name: "code", Type: manifest.ParamTypeString, Pattern: "^[A-Z]+$", Required: true}}, Anchors: []manifest.Anchor{{File: "main.go", Anchor: "// CODEGEN", Insert: "insert.tmpl"}}}}}
	snippets := map[string][]byte{GeneratorsRelPath + "/entity.tmpl": []byte(`{{.Name.Pascal}} {{.Params.count}} {{.Params.enabled}} {{len .Fields}} {{len .Params.tags}} {{.Params.code}}`), GeneratorsRelPath + "/insert.tmpl": []byte("{{.Marker}}\n{{.Name.Pascal}}\n")}
	base := map[string]nativeImage{"main.go": {data: []byte("header\n// CODEGEN\n"), mode: 0o600}}
	makePlan := func() *NativePlan {
		a, _ := ownership.ArtifactFor("main.go", base["main.go"].data, 0o600, "")
		return &NativePlan{before: nativeClone(base), after: nativeClone(base), owned: map[string]ownership.Artifact{"main.go": a}}
	}
	operation := NativeOperation{Kind: "entity", Name: "Widget", Provided: map[string]string{"fields": "name:string", "tags": "red,blue", "code": "ABC"}}
	p := makePlan()
	if err := p.render(tpl, settings.Values{}, manifest.ProjectInfo{}, snippets, []NativeOperation{operation}); err != nil {
		t.Fatal(err)
	}
	if got := string(p.after["internal/widget.go"].data); got != "Widget 2 true 1 2 ABC" {
		t.Fatal(got)
	}
	if p.after["main.go"].mode != 0o600 {
		t.Fatal("anchor mode changed")
	}
	if string(p.before["main.go"].data) != "header\n// CODEGEN\n" {
		t.Fatal("before mutated")
	}
	if err := makePlan().render(tpl, nil, manifest.ProjectInfo{}, snippets, []NativeOperation{operation, operation}); err == nil {
		t.Fatal("duplicate batch accepted")
	}
	for _, provided := range []map[string]string{{"code": "ABC"}, {"fields": "name:unknown", "code": "ABC"}, {"fields": "name:string", "code": "lower"}, {"fields": "name:string", "code": "ABC", "other": "yes"}} {
		op := operation
		op.Provided = provided
		if err := makePlan().render(tpl, nil, manifest.ProjectInfo{}, snippets, []NativeOperation{op}); err == nil {
			t.Fatal("invalid params accepted")
		}
	}
	op := operation
	op.Name = "123Bad"
	if err := makePlan().render(tpl, nil, manifest.ProjectInfo{}, snippets, []NativeOperation{op}); err == nil {
		t.Fatal("invalid name accepted")
	}
}

func TestNativePureMigrationSequenceAndUnsafeTargets(t *testing.T) {
	tpl := &manifest.Template{Generators: []manifest.Generator{{Kind: "migration", Targets: []manifest.Target{{Snippet: "migration.tmpl", Target: "migrations/{{.MigrationSeq}}_{{.Name.Snake}}.sql", Numbered: manifest.NumberedGoose}}}}}
	p := &NativePlan{after: map[string]nativeImage{"migrations": {dir: true, mode: 0o755}, "migrations/00003_prior.sql": {data: []byte("prior"), mode: 0o644}}}
	snippets := map[string][]byte{GeneratorsRelPath + "/migration.tmpl": []byte("{{.MigrationSeq}}")}
	if err := p.render(tpl, nil, manifest.ProjectInfo{}, snippets, []NativeOperation{{Kind: "migration", Name: "One"}, {Kind: "migration", Name: "Two"}}); err != nil {
		t.Fatal(err)
	}
	if string(p.after["migrations/00004_one.sql"].data) != "00004" || string(p.after["migrations/00005_two.sql"].data) != "00005" {
		t.Fatal("batch sequence diverged")
	}
	for _, name := range []string{"../foreign", "/absolute", ".tplaiter/project.yaml", ".git/config", "a\\b", "a\nfile"} {
		if !errors.Is(nativePath(name), ErrNativeOwnership) {
			t.Fatalf("unsafe path accepted: %q", name)
		}
	}
}

func TestNativeZeroValuesAndActionsRefuse(t *testing.T) {
	if _, err := PlanNative(context.Background(), nil, "", nil); !errors.Is(err, ErrNativeIdentityUnavailable) {
		t.Fatal(err)
	}
	if _, _, err := (&NativePlan{}).TransactionMaterial(context.Background()); !errors.Is(err, ErrNativeIdentityUnavailable) {
		t.Fatal(err)
	}
	if !errors.Is((&NativePlan{}).ExecuteAction(context.Background(), NativeAction("shell")), ErrExecutionUnavailable) {
		t.Fatal("generic action accepted")
	}
}

type nativeIdentityInfo struct {
	os.FileInfo
	stat any
}

func (i nativeIdentityInfo) Sys() any { return i.stat }
func TestNativeDeviceIdentity(t *testing.T) {
	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stat := reflect.New(reflect.TypeOf(info.Sys()).Elem())
	dev := stat.Elem().FieldByName("Dev")
	stat.Elem().FieldByName("Ino").SetUint(99)
	values := []uint64{0, 1}
	if dev.Kind() == reflect.Int32 {
		values = append(values, 0x7fffffff, 0xffffffff80000000, 0xffffffffffffffff)
	} else {
		values = append(values, 1<<40, 1<<63, 0xffffffffffffffff)
	}
	for _, want := range values {
		if dev.Kind() == reflect.Int32 {
			if want <= 0x7fffffff {
				dev.SetInt(int64(want))
			} else {
				dev.SetInt(-1 - int64(^want))
			}
		} else {
			dev.SetUint(want)
		}
		fake := nativeIdentityInfo{FileInfo: info, stat: stat.Interface()}
		device, inode := nativeFileID(fake)
		if device != want || inode != 99 {
			t.Fatalf("device identity lost bits: %x", want)
		}
	}
}
