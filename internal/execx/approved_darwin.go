//go:build darwin

package execx

import "encoding/binary"

const nativeArm64SubtypeAll uint32 = 0

// validDarwinNative admits a thin arm64 executable whose loader closure is
// exactly /usr/lib/dyld plus libSystem. It is structural, never a behavioral
// safety claim about the admitted native code.
func validDarwinNative(b []byte) bool {
	if len(b) < 32 || binary.LittleEndian.Uint32(b) != 0xfeedfacf || binary.LittleEndian.Uint32(b[4:]) != 0x0100000c || binary.LittleEndian.Uint32(b[8:]) != nativeArm64SubtypeAll || binary.LittleEndian.Uint32(b[12:]) != 2 {
		return false
	}
	ncmd, size := int(binary.LittleEndian.Uint32(b[16:])), int(binary.LittleEndian.Uint32(b[20:]))
	if ncmd < 1 || ncmd > 4096 || size < 8 || size > len(b)-32 {
		return false
	}
	off, end, dyld, lib := 32, 32+size, false, false
	for i := 0; i < ncmd; i++ {
		if off+8 > end {
			return false
		}
		cmd, n := binary.LittleEndian.Uint32(b[off:]), int(binary.LittleEndian.Uint32(b[off+4:]))
		if n < 8 || n%8 != 0 || off+n > end {
			return false
		}
		switch cmd {
		case 0xe:
			p, ok := machoName(b[off:off+n], 8)
			if !ok || p != "/usr/lib/dyld" || dyld {
				return false
			}
			dyld = true
		case 0xc:
			p, ok := machoName(b[off:off+n], 8)
			if !ok || p != "/usr/lib/libSystem.B.dylib" || lib {
				return false
			}
			lib = true
		case 0x8000001c, 0x80000018, 0x8000001f, 0x80000023, 0x20:
			return false
		}
		off += n
	}
	return off == end && dyld && lib
}
func machoName(c []byte, at int) (string, bool) {
	if len(c) < at+4 {
		return "", false
	}
	start := int(binary.LittleEndian.Uint32(c[at:]))
	if start < at+4 || start >= len(c) {
		return "", false
	}
	end := start
	for end < len(c) && c[end] != 0 {
		end++
	}
	if end == len(c) {
		return "", false
	}
	for _, b := range c[end+1:] {
		if b != 0 {
			return "", false
		}
	}
	return string(c[start:end]), true
}
