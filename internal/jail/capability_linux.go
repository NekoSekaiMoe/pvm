//go:build linux

package jail

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// droppedBoundingCapabilities are removed from the workload's capability
// BOUNDING set (irreversibly, for the whole process tree) right before the
// seccomp filter is installed. Rationale per entry:
//
//	CAP_SYS_PTRACE — the big one. Without it, ptrace is restricted to the
//	  process's OWN descendants (Yama/dumpable rules), which is exactly the
//	  UML SKAS model: guests are clone()d children asking PTRACE_TRACEME.
//	  With it, a compromised monitor running as real root can ptrace ANY
//	  host process and read/write its memory — a full jail escape.
//	CAP_KILL — the jail has no PID namespace, so signal permission would
//	  otherwise extend to host daemons running under other uids.
//	  (Same-uid host processes remain signalable — only a PID/user
//	  namespace closes that fully; see docs in ConfigureProcessIsolation.)
//	CAP_DAC_READ_SEARCH — required by open_by_handle_at for the Landlock
//	  bypass (the syscalls themselves are also seccomp-blocked; this is
//	  belt and braces).
//	CAP_SYS_RAWIO / CAP_SYS_MODULE / CAP_SYS_TIME / CAP_SYS_BOOT /
//	CAP_SYS_PACCT / CAP_SYSLOG / CAP_BPF / CAP_PERFMON / CAP_AUDIT_CONTROL /
//	CAP_AUDIT_WRITE / CAP_MAC_ADMIN / CAP_MAC_OVERRIDE — host-kernel
//	  programming surfaces whose syscalls are already on the seccomp
//	  denylist (or whose device nodes are absent from the jail). UML never
//	  needs any of them.
//	CAP_NET_RAW — the vector tap transport opens /dev/net/tun + ioctl only;
//	  raw AF_PACKET sockets are not used by PVM.
//	CAP_MKNOD — jail device nodes are bind-mounted by the helper pre-exec.
//	CAP_SETUID / CAP_SETGID — SKAS guests share the monitor's uid; the
//	  workload never changes uid/gid.
//	CAP_SYS_NICE — scheduling on own children needs no capability.
//	CAP_SYS_TTY_CONFIG — console termios ioctls on its own fds don't need it
//	  (and the ioctl arg-filter gates the rest).
//
// Deliberately KEPT:
//
//	CAP_NET_ADMIN — TUNSETIFF/TUNSETQUEUE tap attach happens at runtime,
//	  long after exec.
//	CAP_SYS_ADMIN — the breakout-relevant syscalls it gates (mount,
//	  pivot_root, unshare, setns, bpf, ...) are all seccomp-blocked anyway;
//	  dropping it risks subtle runtime breakage for little gain.
//	CAP_DAC_OVERRIDE / CAP_FOWNER — volume-mapped host files may be owned
//	  by other uids; dropping these breaks legitimate reads.
var droppedBoundingCapabilities = []int{
	unix.CAP_SYS_PTRACE,
	unix.CAP_KILL,
	unix.CAP_DAC_READ_SEARCH,
	unix.CAP_SYS_RAWIO,
	unix.CAP_SYS_MODULE,
	unix.CAP_SYS_TIME,
	unix.CAP_SYS_BOOT,
	unix.CAP_SYS_PACCT,
	unix.CAP_SYSLOG,
	unix.CAP_BPF,
	unix.CAP_PERFMON,
	unix.CAP_AUDIT_CONTROL,
	unix.CAP_AUDIT_WRITE,
	unix.CAP_MAC_ADMIN,
	unix.CAP_MAC_OVERRIDE,
	unix.CAP_NET_RAW,
	unix.CAP_MKNOD,
	unix.CAP_SETUID,
	unix.CAP_SETGID,
	unix.CAP_SYS_NICE,
	unix.CAP_SYS_TTY_CONFIG,
}

// DropDangerousCapabilities permanently removes the above capabilities from
// the calling thread's bounding set. Drops require CAP_SETPCAP; a failure
// aborts the launch (fail-closed: the workload must never run with a wider
// bounding set than promised). Bounding-set drops survive execve and are
// irreversible — exactly what the jail handoff needs.
func DropDangerousCapabilities() error {
	for _, cap := range droppedBoundingCapabilities {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(cap), 0, 0, 0); err != nil {
			return fmt.Errorf("capbset drop cap %d: %w", cap, err)
		}
	}
	return nil
}
