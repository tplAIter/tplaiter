//go:build darwin

package execx

import (
	"encoding/binary"
	"testing"
)

func TestDarwinNativeParserRejectsMalformedAndDependencies(t *testing.T) {
	wrongArch := machoFixture("/usr/lib/dyld", "/usr/lib/libSystem.B.dylib", false)
	binary.LittleEndian.PutUint32(wrongArch[4:], 0x01000007)
	for _, raw := range [][]byte{nil, make([]byte, 32), fatFixture(), wrongArch, machoFixture("/wrong/dyld", "/usr/lib/libSystem.B.dylib", false), machoFixture("/usr/lib/dyld", "/usr/lib/libSystem.B.dylib", true), machoFixture("/usr/lib/dyld", "/tmp/evil.dylib", false), machoDependencyFixture(0x80000018), machoDependencyFixture(0x8000001f), machoDependencyFixture(0x80000023), machoDependencyFixture(0x20), malformedCommandFixture(), overlappingCommandFixture()} {
		if validDarwinNative(raw) {
			t.Fatal("invalid native image accepted")
		}
	}
}

func TestDarwinNativeParserAcceptsFiniteEnvelope(t *testing.T) {
	if !validDarwinNative(machoFixture("/usr/lib/dyld", "/usr/lib/libSystem.B.dylib", false)) {
		t.Fatal("finite loader envelope rejected")
	}
}

func TestGofmtDarwinParserAllowsOnlyReviewedLibresolvClosure(t *testing.T) {
	commands := [][]byte{
		machoStringCommand(0xe, "/usr/lib/dyld"),
		machoStringCommand(0xc, "/usr/lib/libSystem.B.dylib"),
		machoStringCommand(0xc, "/usr/lib/libresolv.9.dylib"),
	}
	size := 0
	for _, command := range commands {
		size += len(command)
	}
	image := make([]byte, 32+size)
	binary.LittleEndian.PutUint32(image, 0xfeedfacf)
	binary.LittleEndian.PutUint32(image[4:], 0x0100000c)
	binary.LittleEndian.PutUint32(image[12:], 2)
	binary.LittleEndian.PutUint32(image[16:], uint32(len(commands)))
	binary.LittleEndian.PutUint32(image[20:], uint32(size))
	off := 32
	for _, command := range commands {
		copy(image[off:], command)
		off += len(command)
	}
	if !validGofmtDarwinNative(image) {
		t.Fatal("reviewed gofmt closure rejected")
	}
	if validDarwinNative(image) {
		t.Fatal("native-snapshot branch accepted gofmt-only libresolv closure")
	}
	copy(image[off-len(commands[2])+12:], []byte("/usr/lib/libevil__.dylib\x00"))
	if validGofmtDarwinNative(image) {
		t.Fatal("unreviewed dylib accepted")
	}
}

func TestDarwinNativeParserRejectsIncompatibleCPUSubtype(t *testing.T) {
	b := machoFixture("/usr/lib/dyld", "/usr/lib/libSystem.B.dylib", false)
	binary.LittleEndian.PutUint32(b[8:], 2) // arm64e is outside the declared generic arm64 envelope.
	if validDarwinNative(b) {
		t.Fatal("arm64e accepted by arm64-all runner")
	}
}

func machoFixture(dyld, lib string, rpath bool) []byte {
	commands := [][]byte{machoStringCommand(0xe, dyld), machoStringCommand(0xc, lib)}
	if rpath {
		commands = append(commands, machoStringCommand(0x8000001c, "/tmp"))
	}
	sz := 0
	for _, c := range commands {
		sz += len(c)
	}
	b := make([]byte, 32+sz)
	binary.LittleEndian.PutUint32(b, 0xfeedfacf)
	binary.LittleEndian.PutUint32(b[4:], 0x0100000c)
	binary.LittleEndian.PutUint32(b[12:], 2)
	binary.LittleEndian.PutUint32(b[16:], uint32(len(commands)))
	binary.LittleEndian.PutUint32(b[20:], uint32(sz))
	o := 32
	for _, c := range commands {
		copy(b[o:], c)
		o += len(c)
	}
	return b
}

func machoStringCommand(cmd uint32, value string) []byte {
	n := 12 + len(value) + 1
	if rem := n % 8; rem != 0 {
		n += 8 - rem
	}
	b := make([]byte, n)
	binary.LittleEndian.PutUint32(b, cmd)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	binary.LittleEndian.PutUint32(b[8:], 12)
	copy(b[12:], value)
	return b
}

func machoDependencyFixture(cmd uint32) []byte {
	b := machoFixture("/usr/lib/dyld", "/usr/lib/libSystem.B.dylib", false)
	c := machoStringCommand(cmd, "/usr/lib/libBad.dylib")
	binary.LittleEndian.PutUint32(b[16:], 3)
	binary.LittleEndian.PutUint32(b[20:], uint32(len(b)-32+len(c)))
	return append(b, c...)
}

func malformedCommandFixture() []byte {
	b := machoFixture("/usr/lib/dyld", "/usr/lib/libSystem.B.dylib", false)
	binary.LittleEndian.PutUint32(b[36:], 4)
	return b
}

func overlappingCommandFixture() []byte {
	b := machoFixture("/usr/lib/dyld", "/usr/lib/libSystem.B.dylib", false)
	binary.LittleEndian.PutUint32(b[36:], uint32(len(b)))
	return b
}

func fatFixture() []byte { b := make([]byte, 32); binary.BigEndian.PutUint32(b, 0xcafebabe); return b }
