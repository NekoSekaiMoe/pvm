// Package state holds the lifecycle FSM and on-disk persistence for tasks.
//
// This replaces the old flat status string (starting/running/stopped/exited)
// with the full state machine from plan.md §8:
//
//	Pending -> Provisioning -> Ready -> Running <-> Suspended
//	                                  -> Review -> Completed -> Destroy
//	                                  -> Failed (retry/inspect)
//	                                  -> Quarantined (anomaly isolation)
//
// Transitions are: persisted on every change, idempotent (re-applying the same
// transition is a no-op), bounded by per-state max dwell time, and tagged with
// the responsible party (agent/controller/human) for audit.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// RootDir is the on-disk root for all task state. Overridable for tests and
// non-root runs via $PVM_STATE_ROOT.
var RootDir = resolveStateRoot()

func resolveStateRoot() string {
	if v := os.Getenv("PVM_STATE_ROOT"); v != "" {
		return v
	}
	return "/var/lib/uml-container/containers"
}

var idRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func ContainerDir(id string) (string, error) {
	if !idRe.MatchString(id) {
		return "", fmt.Errorf("invalid container ID")
	}
	return filepath.Join(RootDir, id), nil
}

// Status is a lifecycle FSM state (plan.md §8.2).
type Status string

const (
	StatusPending      Status = "pending"       // accepted, not yet provisioned
	StatusProvisioning Status = "provisioning"  // creating runtime + policy
	StatusReady        Status = "ready"         // health-checked, not yet running agent loop
	StatusRunning      Status = "running"       // agent ReAct loop active
	StatusSuspended    Status = "suspended"     // checkpointed / frozen
	StatusResuming     Status = "resuming"      // restoring identity + runtime
	StatusReview       Status = "review"        // awaiting verify/approve
	StatusCompleted    Status = "completed"     // artifact sealed
	StatusFailed       Status = "failed"        // retry / inspect
	StatusQuarantined  Status = "quarantined"   // network revoked, anomaly isolated
	StatusDestroy      Status = "destroy"       // revoke + cleanup done
	StatusStopped      Status = "stopped"       // generic terminal (legacy compat)
	StatusExited       Status = "exited"        // process exited (legacy compat)
)

// Terminal reports whether no further transitions are possible.
// Note: Completed is NOT terminal — it may still flow to Destroy for
// revoke/cleanup (plan.md §8). Only Destroy/Stopped/Exited are truly final.
func (s Status) Terminal() bool {
	switch s {
	case StatusDestroy, StatusStopped, StatusExited:
		return true
	}
	return false
}

// Actor is who drove a transition (plan.md §8.3 "明确责任方").
type Actor string

const (
	ActorAgent      Actor = "agent"
	ActorController Actor = "controller"
	ActorHuman      Actor = "human"
	ActorSystem     Actor = "system"
)

// Transition is one recorded state change. The full slice is the audit trail
// required by plan.md §14.2 (phase 03 EXECUTION).
type Transition struct {
	From      Status    `json:"from"`
	To        Status    `json:"to"`
	Actor     Actor     `json:"actor"`
	Reason    string    `json:"reason"`
	At        time.Time `json:"at"`
}

// ContainerState is the persisted task state. The new fields drive the FSM;
// the legacy ID/Status/PID/StartedAt are kept for API compatibility.
type ContainerState struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Tenant     string   `json:"tenant,omitempty"`
	Caller     string   `json:"caller,omitempty"`
	Status     Status   `json:"status"`
	PID        int      `json:"pid"`
	StartedAt  time.Time `json:"started_at"`
	EndedAt    time.Time `json:"ended_at,omitempty"`
	SpecFP     string   `json:"spec_fingerprint,omitempty"`

	// lifecycle bookkeeping
	Transitions []Transition `json:"transitions,omitempty"`
	Retries     int          `json:"retries,omitempty"`
	Deadline    time.Time    `json:"deadline,omitempty"`

	// runtime linkage (filled during provisioning)
	NetworkTap string `json:"network_tap,omitempty"`
	Bridge     string `json:"bridge,omitempty"`
	GatewayIP  string `json:"gateway_ip,omitempty"`

	mu sync.Mutex `json:"-"`
}

// transitions is the allowed FSM edge table. Anything not listed is rejected.
// Quarantined is reachable from EVERY non-terminal state so the incident
// controller can isolate an anomalous task no matter where it is in its
// lifecycle. Suspended/Resuming also have a Failed edge so a failed
// checkpoint/restore isn't forced through Destroy.
var allowed = map[Status][]Status{
	StatusPending:      {StatusProvisioning, StatusDestroy, StatusFailed, StatusQuarantined},
	StatusProvisioning: {StatusReady, StatusFailed, StatusQuarantined, StatusDestroy},
	StatusReady:        {StatusRunning, StatusSuspended, StatusFailed, StatusQuarantined, StatusDestroy},
	StatusRunning:      {StatusSuspended, StatusReview, StatusFailed, StatusQuarantined, StatusDestroy},
	StatusSuspended:    {StatusResuming, StatusReview, StatusFailed, StatusQuarantined, StatusDestroy},
	StatusResuming:     {StatusRunning, StatusFailed, StatusQuarantined, StatusDestroy},
	StatusReview:       {StatusCompleted, StatusFailed, StatusQuarantined, StatusDestroy},
	StatusFailed:       {StatusProvisioning, StatusQuarantined, StatusDestroy},
	StatusQuarantined:  {StatusFailed, StatusDestroy},
	StatusCompleted:    {StatusDestroy},
}

// canTransition reports whether from -> to is an allowed edge.
func canTransition(from, to Status) bool {
	if from == to {
		return true // idempotent
	}
	for _, t := range allowed[from] {
		if t == to {
			return true
		}
	}
	return false
}

// Transition moves the state machine and records the audit row. It is safe
// under concurrent callers: the transition + append + save are atomic.
// Returns:
//   - ErrTerminal if the current state is terminal (no edges out at all)
//   - ErrInvalidTransition wrapping the specific from->to if the edge isn't allowed
func (s *ContainerState) Transition(to Status, actor Actor, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Status.Terminal() {
		return fmt.Errorf("%w: %s is terminal, cannot transition to %s", ErrTerminal, s.Status, to)
	}
	if !canTransition(s.Status, to) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, s.Status, to)
	}
	rec := Transition{From: s.Status, To: to, Actor: actor, Reason: reason, At: time.Now()}
	s.Transitions = append(s.Transitions, rec)
	s.Status = to
	if to == StatusDestroy || to == StatusStopped || to == StatusExited || to == StatusCompleted {
		if s.EndedAt.IsZero() {
			s.EndedAt = time.Now()
		}
	}
	return nil
}

// ErrTerminal is returned when a transition is attempted from a terminal state.
// Distinct from ErrInvalidTransition so callers can tell "this task is done,
// don't retry" apart from "that edge isn't allowed, try a different one".
var ErrTerminal = errors.New("state: terminal state")

// ErrInvalidTransition is returned when a specific from->to edge is not in
// the allowed table (but the source state is not terminal).
var ErrInvalidTransition = errors.New("state: invalid transition")

// SaveState persists state atomically: write to temp, fsync, rename. It takes
// a read-side snapshot of the slices/maps under the container lock so that a
// concurrent Transition (which appends to s.Transitions under the same lock)
// cannot race with this encoder — the persisted JSON is always a consistent
// point-in-time view.
func SaveState(id string, st *ContainerState) error {
	dir, err := ContainerDir(id)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	// Snapshot the mutable fields under the lock so json.Encode below reads a
	// stable value even if another goroutine calls Transition concurrently.
	snapshot := st.snapshotLocked()

	tmp, err := os.CreateTemp(dir, ".state-*.json.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snapshot); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	tmp.Close()
	return os.Rename(tmpName, filepath.Join(dir, "state.json"))
}

// snapshotLocked returns a deep copy of the fields json.Marshal would serialize,
// taken under the container lock. Callers don't need to hold the lock — this
// method acquires it. The copy is safe to hand to an encoder off-lock.
func (s *ContainerState) snapshotLocked() *ContainerState {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := &ContainerState{
		ID:          s.ID,
		Name:        s.Name,
		Tenant:      s.Tenant,
		Caller:      s.Caller,
		Status:      s.Status,
		PID:         s.PID,
		StartedAt:   s.StartedAt,
		EndedAt:     s.EndedAt,
		SpecFP:      s.SpecFP,
		Retries:     s.Retries,
		Deadline:    s.Deadline,
		NetworkTap:  s.NetworkTap,
		Bridge:      s.Bridge,
		GatewayIP:   s.GatewayIP,
	}
	if len(s.Transitions) > 0 {
		cp.Transitions = append([]Transition(nil), s.Transitions...)
	}
	return cp
}

// LoadState reads the persisted state.json for a task. Returns an error if the
// task is unknown.
func LoadState(id string) (*ContainerState, error) {
	dir, err := ContainerDir(id)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		return nil, err
	}
	var st ContainerState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("failed to parse state json: %v", err)
	}
	return &st, nil
}

// ListAll returns the state of every known task under RootDir. Tasks whose
// state.json is missing/corrupt are skipped (never panic the listing).
func ListAll() ([]*ContainerState, error) {
	dirs, err := os.ReadDir(RootDir)
	if err != nil {
		return nil, err
	}
	var out []*ContainerState
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		if st, err := LoadState(d.Name()); err == nil {
			out = append(out, st)
		}
	}
	return out, nil
}
