package state

// pid.go — PID identity bookkeeping for persisted task state.
//
// A ContainerState records the guest PID at launch, and later control
// paths act on that number: deep pause checkpoints and SIGKILLs it, the
// watchdog inspects it, snapshots freeze it. Between the record and the
// act, the process can die and the kernel can hand the SAME pid to an
// unrelated process — acting on a recycled pid would checkpoint or kill
// an innocent victim. The kernel exposes a stable identity for a process:
// field 22 of /proc/<pid>/stat (starttime, clock ticks since boot), which
// is unique per process lifetime. StampPID records it next to the pid;
// PIDIdentityOK refuses to act when the pair no longer matches.

import (
	"fmt"
	"os"
	"strings"
)

// MetaPIDStart is the ContainerState.Metadata key holding the recorded
// /proc starttime of the process named by ContainerState.PID.
const MetaPIDStart = "pid_start"

// ProcStartTime returns field 22 of /proc/<pid>/stat (the process start
// time in clock ticks since boot) as a string token. The comm field is
// parenthesized and may itself contain spaces and parens, so the record
// is split after the LAST closing paren, not on whitespace.
func ProcStartTime(pid int) (string, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	s := string(raw)
	// Cut "pid (comm) ..." at the last ')': everything after starts at
	// field 3 (state).
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 > len(s) {
		return "", fmt.Errorf("state: malformed /proc/%d/stat", pid)
	}
	fields := strings.Fields(s[i+2:])
	// starttime is field 22; fields[0] is field 3 → index 22-3 = 19.
	const want = 20
	if len(fields) < want {
		return "", fmt.Errorf("state: short /proc/%d/stat (%d fields after comm)", pid, len(fields))
	}
	return fields[19], nil
}

// StampPID records pid (and its /proc starttime, when readable) on st.
// It replaces every direct `st.PID = pid` assignment so recycled-pid
// detection works uniformly. When the starttime cannot be read (procfs
// hidden, exotic kernel) the stamp is cleared: PIDIdentityOK then
// degrades to the legacy existence-only check rather than lying.
func StampPID(st *ContainerState, pid int) {
	if st == nil {
		return
	}
	st.PID = pid
	if st.Metadata == nil {
		st.Metadata = map[string]string{}
	}
	if start, err := ProcStartTime(pid); err == nil {
		st.Metadata[MetaPIDStart] = start
	} else {
		delete(st.Metadata, MetaPIDStart)
	}
}

// PIDIdentityOK reports whether st.PID still names the process that was
// stamped: the pid must exist AND, when a starttime was recorded, match
// it. States written before this bookkeeping existed (no recorded
// starttime) get the weaker existence-only verdict — the process is
// there, we just cannot prove it is the original one.
func PIDIdentityOK(st *ContainerState) bool {
	if st == nil || st.PID <= 0 {
		return false
	}
	live, err := ProcStartTime(st.PID)
	if err != nil {
		return false // gone (or unreadable): not ours to touch
	}
	recorded := st.Metadata[MetaPIDStart]
	if recorded == "" {
		return true // legacy state: existence is all we know
	}
	return recorded == live
}
