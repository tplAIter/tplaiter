//go:build linux

package execx

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"testing"
)

// elfHelper builds a real static helper through the Go toolchain; its bytes
// are the baseline that the malformed variants below mutate.
func elfHelper(t *testing.T) []byte {
	t.Helper()
	return buildApprovedHelper(t, "package main\nimport \"syscall\"\nfunc main(){syscall.Write(1,[]byte(\"ok\"))}\n")
}

func elfPhdr(t *testing.T, b []byte, index int) []byte {
	t.Helper()
	phoff := binary.LittleEndian.Uint64(b[32:])
	phentsize := int(binary.LittleEndian.Uint16(b[54:]))
	phnum := int(binary.LittleEndian.Uint16(b[56:]))
	if index >= phnum || phentsize < 56 {
		t.Fatalf("program header %d out of range (phnum=%d entsize=%d)", index, phnum, phentsize)
	}
	start := int(phoff) + index*phentsize
	return b[start : start+phentsize]
}

func elfFindPhdr(t *testing.T, b []byte, typ elf.ProgType, flags elf.ProgFlag) int {
	t.Helper()
	phnum := int(binary.LittleEndian.Uint16(b[56:]))
	for i := 0; i < phnum; i++ {
		h := elfPhdr(t, b, i)
		if elf.ProgType(binary.LittleEndian.Uint32(h)) == typ && elf.ProgFlag(binary.LittleEndian.Uint32(h[4:]))&flags == flags {
			return i
		}
	}
	t.Fatalf("no program header type=%v flags=%v", typ, flags)
	return -1
}

func TestLinuxNativeEnvelopeAcceptsStaticHostELF(t *testing.T) {
	tool := elfHelper(t)
	if !validNativeTool(tool) || !validGofmtNative(tool) {
		t.Fatal("static host-architecture ELF rejected")
	}
}

func TestLinuxNativeEnvelopeRejectsMalformedForeignAndDynamic(t *testing.T) {
	base := elfHelper(t)
	mutate := func(f func([]byte)) []byte {
		b := append([]byte(nil), base...)
		f(b)
		return b
	}
	foreign := uint16(elf.EM_X86_64)
	if machine, _ := linuxNativeMachine(); machine == elf.EM_X86_64 {
		foreign = uint16(elf.EM_AARCH64)
	}
	cases := map[string][]byte{
		"empty":        nil,
		"short":        base[:63],
		"bad-magic":    mutate(func(b []byte) { b[0] = 0 }),
		"class32":      mutate(func(b []byte) { b[4] = byte(elf.ELFCLASS32) }),
		"big-endian":   mutate(func(b []byte) { b[5] = byte(elf.ELFDATA2MSB) }),
		"foreign-arch": mutate(func(b []byte) { binary.LittleEndian.PutUint16(b[18:], foreign) }),
		"shared-object": mutate(func(b []byte) {
			binary.LittleEndian.PutUint16(b[16:], uint16(elf.ET_DYN))
		}),
		"zero-entry": mutate(func(b []byte) { binary.LittleEndian.PutUint64(b[24:], 0) }),
		"foreign-osabi": mutate(func(b []byte) {
			b[7] = byte(elf.ELFOSABI_FREEBSD)
		}),
		"interpreter": mutate(func(b []byte) {
			h := elfPhdr(t, b, elfFindPhdr(t, b, elf.PT_LOAD, 0))
			binary.LittleEndian.PutUint32(h, uint32(elf.PT_INTERP))
		}),
		"dynamic": mutate(func(b []byte) {
			h := elfPhdr(t, b, elfFindPhdr(t, b, elf.PT_LOAD, 0))
			binary.LittleEndian.PutUint32(h, uint32(elf.PT_DYNAMIC))
		}),
		"writable-text": mutate(func(b []byte) {
			h := elfPhdr(t, b, elfFindPhdr(t, b, elf.PT_LOAD, elf.PF_X))
			binary.LittleEndian.PutUint32(h[4:], uint32(elf.PF_R|elf.PF_W|elf.PF_X))
		}),
		"segment-past-eof": mutate(func(b []byte) {
			h := elfPhdr(t, b, elfFindPhdr(t, b, elf.PT_LOAD, elf.PF_X))
			binary.LittleEndian.PutUint64(h[32:], uint64(len(b))+1)
			binary.LittleEndian.PutUint64(h[40:], uint64(len(b))+1)
		}),
		"no-executable-segment": mutate(func(b []byte) {
			h := elfPhdr(t, b, elfFindPhdr(t, b, elf.PT_LOAD, elf.PF_X))
			binary.LittleEndian.PutUint32(h[4:], uint32(elf.PF_R))
		}),
		"mach-o": {0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01},
	}
	for name, raw := range cases {
		if validNativeTool(raw) || validGofmtNative(raw) {
			t.Errorf("%s: invalid native image accepted", name)
		}
	}
}

// A distribution binary linked against the system loader is the canonical
// dynamic case; it must be refused by structure, not by a path allowlist.
func TestLinuxNativeEnvelopeRejectsSystemDynamicBinary(t *testing.T) {
	for _, path := range []string{"/bin/sleep", "/usr/bin/env", "/bin/sh"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		f, err := elf.NewFile(bytes.NewReader(raw))
		if err != nil {
			continue
		}
		dynamic := false
		for _, p := range f.Progs {
			if p.Type == elf.PT_INTERP {
				dynamic = true
			}
		}
		_ = f.Close()
		if !dynamic {
			continue
		}
		if validNativeTool(raw) {
			t.Fatalf("dynamically linked %s accepted", path)
		}
		return
	}
	t.Skip("environment: no dynamically linked system binary found to exercise the loader refusal")
}

func TestLinuxApprovedPathForFDRefusesUnlinked(t *testing.T) {
	dir := t6BTempDir(t)
	f, err := os.CreateTemp(dir, "held-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	path, err := approvedPathForFD(int(f.Fd()))
	if err != nil || path != f.Name() {
		t.Fatalf("held path=%q err=%v want %q", path, err, f.Name())
	}
	if err := os.Remove(f.Name()); err != nil {
		t.Fatal(err)
	}
	if path, err := approvedPathForFD(int(f.Fd())); err == nil {
		t.Fatalf("unlinked descriptor resolved to %q", path)
	}
	if _, err := approvedPathForFD(-1); err == nil {
		t.Fatal("negative descriptor resolved")
	}
}
