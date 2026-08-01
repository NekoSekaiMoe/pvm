package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestContainerDir(t *testing.T) {
	dir, err := ContainerDir("valid-id_123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := filepath.Join(RootDir, "valid-id_123")
	if dir != expected {
		t.Errorf("Expected %s, got %s", expected, dir)
	}
	if _, err := ContainerDir("../invalid"); err == nil {
		t.Errorf("Expected error for invalid ID, got nil")
	}
}

func TestFSM_ValidTransitions(t *testing.T) {
	cases := []struct{ from, to Status }{
		{StatusPending, StatusProvisioning},
		{StatusProvisioning, StatusReady},
		{StatusReady, StatusRunning},
		{StatusRunning, StatusSuspended},
		{StatusSuspended, StatusResuming},
		{StatusResuming, StatusRunning},
		{StatusRunning, StatusReview},
		{StatusReview, StatusCompleted},
		{StatusRunning, StatusQuarantined},
		{StatusQuarantined, StatusDestroy},
	}
	for _, c := range cases {
		if !canTransition(c.from, c.to) {
			t.Errorf("expected %s -> %s to be allowed", c.from, c.to)
		}
	}
}

func TestFSM_InvalidTransitions(t *testing.T) {
	cases := []struct{ from, to Status }{
		{StatusPending, StatusRunning},       // must provision first
		{StatusRunning, StatusReady},         // can't un-start
		{StatusCompleted, StatusRunning},     // terminal
		{StatusDestroy, StatusPending},       // terminal
		{StatusReady, StatusCompleted},       // must run + review
	}
	for _, c := range cases {
		if canTransition(c.from, c.to) {
			t.Errorf("expected %s -> %s to be REJECTED", c.from, c.to)
		}
	}
}

func TestTransition_RecordsAudit(t *testing.T) {
	s := &ContainerState{ID: "x", Status: StatusPending}
	if err := s.Transition(StatusProvisioning, ActorController, "kickoff"); err != nil {
		t.Fatalf("transition: %v", err)
	}
	if s.Status != StatusProvisioning {
		t.Fatalf("status = %s", s.Status)
	}
	if len(s.Transitions) != 1 {
		t.Fatalf("expected 1 transition record, got %d", len(s.Transitions))
	}
	if s.Transitions[0].Actor != ActorController {
		t.Errorf("actor = %s", s.Transitions[0].Actor)
	}

	// idempotent re-transition to same state appends another record but is allowed.
	if err := s.Transition(StatusProvisioning, ActorController, "reapply"); err != nil {
		t.Fatalf("idempotent: %v", err)
	}
}

func TestTransition_TerminalRejected(t *testing.T) {
	s := &ContainerState{ID: "x", Status: StatusDestroy}
	err := s.Transition(StatusRunning, ActorAgent, "revive")
	if err == nil {
		t.Fatal("expected error reviving terminal state")
	}
	if !errors.Is(err, ErrTerminal) {
		t.Errorf("terminal rejection must be ErrTerminal, got: %v", err)
	}
	if errors.Is(err, ErrInvalidTransition) {
		t.Errorf("terminal rejection must NOT be ErrInvalidTransition")
	}
}

func TestTransition_InvalidEdgeIsDistinctFromTerminal(t *testing.T) {
	// A non-terminal state with a forbidden edge must return ErrInvalidTransition,
	// NOT ErrTerminal — so callers can tell "retry with a different edge" apart
	// from "the task is dead".
	s := &ContainerState{ID: "x", Status: StatusPending}
	err := s.Transition(StatusRunning, ActorAgent, "skip provisioning")
	if err == nil {
		t.Fatal("expected invalid transition")
	}
	if !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("expected ErrInvalidTransition, got %v", err)
	}
	if errors.Is(err, ErrTerminal) {
		t.Errorf("invalid edge must NOT be ErrTerminal")
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	tmp := t.TempDir()
	old := RootDir
	RootDir = tmp
	defer func() { RootDir = old }()

	s := &ContainerState{ID: "rt", Status: StatusPending}
	if err := SaveState("rt", s); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := LoadState("rt")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Status != StatusPending {
		t.Errorf("status = %s", got.Status)
	}
	// state.json exists at the expected path
	if _, err := os.Stat(filepath.Join(tmp, "rt", "state.json")); err != nil {
		t.Errorf("state.json missing: %v", err)
	}
}

func TestListAll_SkipsCorrupt(t *testing.T) {
	tmp := t.TempDir()
	old := RootDir
	RootDir = tmp
	defer func() { RootDir = old }()

	// one good, one corrupt
	_ = SaveState("good", &ContainerState{ID: "good", Status: StatusPending})
	os.MkdirAll(filepath.Join(tmp, "bad"), 0755)
	os.WriteFile(filepath.Join(tmp, "bad", "state.json"), []byte("{not json"), 0644)

	all, err := ListAll()
	if err != nil {
		t.Fatalf("listall: %v", err)
	}
	if len(all) != 1 || all[0].ID != "good" {
		t.Errorf("expected only [good], got %+v", all)
	}
}
