//go:build linux

package execx

import (
	"bytes"
	"debug/elf"
	"errors"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// linuxNativeMachine is the only ELF machine the Linux approved runner admits:
// the host architecture. A foreign-architecture image would need an emulator
// (binfmt_misc), which is outside the approved envelope.
func linuxNativeMachine() (elf.Machine, bool) {
	switch runtime.GOARCH {
	case "amd64":
		return elf.EM_X86_64, true
	case "arm64":
		return elf.EM_AARCH64, true
	default:
		return 0, false
	}
}

// validNativeTool admits the native-snapshot tool on Linux: a statically
// linked 64-bit little-endian ELF executable for the host machine. The loader
// closure is exactly the kernel: there is no PT_INTERP (dynamic loader) and no
// PT_DYNAMIC (shared-library dependencies, RPATH/RUNPATH, or a static-pie
// self-relocation table). Like the Darwin policy this is a structural
// admission check, never a behavioral safety claim about the admitted code.
func validNativeTool(b []byte) bool { return validLinuxStaticELF(b) }

// validGofmtNative uses the same closed static envelope: gofmt built with
// CGO_ENABLED=0 has no dynamic dependencies on Linux, so no reviewed
// exception (Darwin's libresolv) is needed.
func validGofmtNative(b []byte) bool { return validLinuxStaticELF(b) }

func validLinuxStaticELF(b []byte) (ok bool) {
	machine, supported := linuxNativeMachine()
	if !supported || len(b) < 64 || !bytes.HasPrefix(b, []byte(elf.ELFMAG)) {
		return false
	}
	// debug/elf reports malformed input as errors; the recover is a second
	// fence so a parser defect on hostile bytes still fails closed.
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		return false
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Version != elf.EV_CURRENT || f.Machine != machine || f.Type != elf.ET_EXEC || f.Entry == 0 {
		return false
	}
	if f.OSABI != elf.ELFOSABI_NONE && f.OSABI != elf.ELFOSABI_LINUX {
		return false
	}
	executable := false
	for _, p := range f.Progs {
		switch p.Type {
		case elf.PT_INTERP, elf.PT_DYNAMIC:
			return false
		case elf.PT_LOAD:
			if p.Filesz > p.Memsz || p.Off+p.Filesz < p.Off || p.Off+p.Filesz > uint64(len(b)) {
				return false
			}
			if p.Flags&elf.PF_X != 0 {
				if p.Flags&elf.PF_W != 0 {
					return false // writable and executable segment
				}
				executable = true
			}
		default:
			// Notes, stack, RELRO, TLS and similar segments carry no loader or
			// dependency semantics.
		}
	}
	return executable
}

// approvedPathForFD resolves a held descriptor through /proc/self/fd and
// accepts the result only when it is an absolute clean path that still names
// the same inode. Unlinked objects (" (deleted)") and pseudo-files fail
// closed, as does a host without a mounted procfs.
func approvedPathForFD(fd int) (string, error) {
	if fd < 0 {
		return "", errors.New("invalid descriptor")
	}
	buf := make([]byte, unix.PathMax)
	n, err := unix.Readlink("/proc/self/fd/"+strconv.Itoa(fd), buf)
	if err != nil {
		return "", err
	}
	if n <= 0 || n >= len(buf) {
		return "", errors.New("unresolvable fd path")
	}
	path := string(buf[:n])
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.HasSuffix(path, " (deleted)") {
		return "", errors.New("unresolvable fd path")
	}
	var held, named unix.Stat_t
	if unix.Fstat(fd, &held) != nil || unix.Lstat(path, &named) != nil || held.Dev != named.Dev || held.Ino != named.Ino {
		return "", errors.New("fd path does not match its inode")
	}
	return path, nil
}
