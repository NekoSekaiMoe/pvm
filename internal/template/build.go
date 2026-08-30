package template

// build.go turns PENDING template records into READY ones (bucket-3 "模板
// 永远 PENDING"): a Builder goroutine drives the pipeline
//
//	queued -> pull/verify -> extract/mkfs (image.Pull) -> done
//
// persisting progress to <templateDir>/build.json (phase, pct, log_tail) and
// a full build.log. Two image classes are supported:
//
//   - image_ref is an existing rootfs path (e.g. an .img produced by
//     `umlctl image pull`): the file is verified and bound directly (no
//     root needed);
//   - image_ref is a Docker/tarball reference: delegated to image.Pull
//     (root required for loop-mount extraction; the already-exists fast
//     path lets CI pre-seed the store and complete builds unprivileged).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"uml-container/internal/fsjson"
	"uml-container/internal/image"
	"uml-container/internal/metrics"
)

// Build phases (mirrored by the WebUI progress bar and `agentpvm template
// watch`).
const (
	PhaseQueued  = "queued"
	PhaseVerify  = "verify"
	PhasePull    = "pull"
	PhaseExtract = "extract"
	PhaseDone    = "done"
	PhaseFailed  = "failed"
)

// BuildStatus is the persisted progress record.
type BuildStatus struct {
	Phase     string    `json:"phase"`
	Pct       int       `json:"pct"`
	LogTail   string    `json:"log_tail,omitempty"`
	Error     string    `json:"error,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

var metricTemplateBuilds = metrics.Counter("pvm_template_builds_total", "Template builds started", "outcome")

// Builder serializes per-template builds (one build per template at a time)
// and exposes progress.
type Builder struct {
	mu      sync.Mutex
	running map[string]bool
}

var defaultBuilder = &Builder{running: map[string]bool{}}

// DefaultBuilder returns the process-global builder.
func DefaultBuilder() *Builder { return defaultBuilder }

// Update applies mutate to the record under the store lock and persists it.
// Generic on purpose: build flips Status/ImagePath, alias management keeps
// using its own paths.
func (s *Store) Update(id string, mutate func(*Record) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.getLocked(id)
	if err != nil {
		return err
	}
	before := *rec
	if err := mutate(rec); err != nil {
		*rec = before
		return err
	}
	if err := s.validateRecordLocked(rec); err != nil {
		*rec = before
		return err
	}
	dir, err := s.dir(id)
	if err != nil {
		*rec = before
		return err
	}
	return writeMeta(dir, *rec)
}

// validateRecordLocked centralizes the invariant checks shared by Create and
// Update.
func (s *Store) validateRecordLocked(rec *Record) error {
	if rec.TemplateID == "" {
		return fmt.Errorf("%w: empty template id", ErrInvalid)
	}
	switch rec.Status {
	case "", "READY", "PENDING", "FAILED":
	default:
		return fmt.Errorf("%w: status %q (must be READY, PENDING or FAILED)", ErrInvalid, rec.Status)
	}
	switch rec.Kind {
	case "", "template", "snapshot":
	default:
		return fmt.Errorf("%w: kind %q (must be template or snapshot)", ErrInvalid, rec.Kind)
	}
	if rec.Status == "READY" && rec.Alias != "" {
		if err := validateAlias(rec.Alias); err != nil {
			return err
		}
		if other, err := s.getByAliasLocked(rec.Alias); err == nil && other.TemplateID != rec.TemplateID {
			return fmt.Errorf("%w: alias %q already bound to %s", ErrConflict, rec.Alias, other.TemplateID)
		}
	}
	return nil
}

// buildDir returns the template's directory for progress files.
func buildDir(s *Store, id string) (string, error) { return s.dir(id) }

// Start launches the async build for a PENDING template. Returns an error
// when the record is missing, not PENDING, or a build is already running.
func (b *Builder) Start(s *Store, id string) error {
	rec, err := s.Get(id)
	if err != nil {
		return err
	}
	if rec.Status != "PENDING" {
		return fmt.Errorf("%w: template %s is %s, not PENDING", ErrInvalid, id, rec.Status)
	}
	b.mu.Lock()
	if b.running[id] {
		b.mu.Unlock()
		return fmt.Errorf("%w: build already running for %s", ErrConflict, id)
	}
	b.running[id] = true
	b.mu.Unlock()

	go func() {
		defer func() {
			b.mu.Lock()
			delete(b.running, id)
			b.mu.Unlock()
		}()
		b.run(s, id, rec.ImageRef)
	}()
	return nil
}

// WaitIdle blocks until no build is in flight for this builder (bounded by
// timeout). It is the quiescence barrier tests and operators use before
// tearing down a store root — Status/Wait alone can return at the terminal
// marker while the goroutine still has trailing writes (final Update,
// running-map cleanup).
func (b *Builder) WaitIdle(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		b.mu.Lock()
		n := len(b.running)
		b.mu.Unlock()
		if n == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("template: %d build(s) still running after %s", n, timeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Status reads the persisted build progress.
func (b *Builder) Status(s *Store, id string) (*BuildStatus, error) {
	dir, err := buildDir(s, id)
	if err != nil {
		return nil, err
	}
	var st BuildStatus
	raw, err := os.ReadFile(filepath.Join(dir, "build.json"))
	if err != nil {
		// No build file yet: synthesize from the record.
		rec, gerr := s.Get(id)
		if gerr != nil {
			return nil, gerr
		}
		switch rec.Status {
		case "READY":
			return &BuildStatus{Phase: PhaseDone, Pct: 100, UpdatedAt: time.Now().UTC()}, nil
		case "FAILED":
			return &BuildStatus{Phase: PhaseFailed, Pct: 100, UpdatedAt: time.Now().UTC()}, nil
		default:
			return &BuildStatus{Phase: PhaseQueued, Pct: 0, UpdatedAt: time.Now().UTC()}, nil
		}
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Wait blocks until the build reaches a terminal phase or timeout.
func (b *Builder) Wait(s *Store, id string, timeout time.Duration) (*BuildStatus, error) {
	deadline := time.Now().Add(timeout)
	for {
		st, err := b.Status(s, id)
		if err != nil {
			return nil, err
		}
		if st.Phase == PhaseDone || st.Phase == PhaseFailed {
			return st, nil
		}
		if time.Now().After(deadline) {
			return st, nil
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// run drives one build to completion.
func (b *Builder) run(s *Store, id, imageRef string) {
	fail := func(format string, args ...interface{}) {
		reason := fmt.Sprintf(format, args...)
		metricTemplateBuilds.Inc("failed")
		b.progress(s, id, BuildStatus{Phase: PhaseFailed, Pct: 100, Error: reason, UpdatedAt: time.Now().UTC()}, reason)
		_ = s.Update(id, func(r *Record) error { r.Status = "FAILED"; return nil })
	}
	b.log(s, id, fmt.Sprintf("build start: image_ref=%q", imageRef))
	b.progress(s, id, BuildStatus{Phase: PhaseQueued, Pct: 5, UpdatedAt: time.Now().UTC()}, "queued")

	if strings.TrimSpace(imageRef) == "" {
		fail("no image_ref on template record")
		return
	}

	// Rootfs-path class: bind an existing image file directly.
	if fi, err := os.Stat(imageRef); err == nil && !fi.IsDir() {
		b.progress(s, id, BuildStatus{Phase: PhaseVerify, Pct: 50, UpdatedAt: time.Now().UTC()}, "verifying rootfs path")
		if fi.Size() == 0 {
			fail("rootfs %s is empty", imageRef)
			return
		}
		b.log(s, id, "rootfs path verified ("+fmt.Sprint(fi.Size())+" bytes)")
		_ = s.Update(id, func(r *Record) error { r.ImagePath = imageRef; return nil })
		b.finish(s, id)
		return
	}

	// Docker/tarball reference class.
	b.progress(s, id, BuildStatus{Phase: PhasePull, Pct: 30, UpdatedAt: time.Now().UTC()}, "pulling image")
	if err := image.Pull(imageRef); err != nil {
		fail("image pull failed: %v", err)
		return
	}
	b.progress(s, id, BuildStatus{Phase: PhaseExtract, Pct: 80, UpdatedAt: time.Now().UTC()}, "image ready in store")
	storePath, err := image.StorePath(imageRef)
	if err != nil {
		fail("resolve store path: %v", err)
		return
	}
	_ = s.Update(id, func(r *Record) error { r.ImagePath = storePath; return nil })
	b.finish(s, id)
}

func (b *Builder) finish(s *Store, id string) {
	metricTemplateBuilds.Inc("done")
	b.progress(s, id, BuildStatus{Phase: PhaseDone, Pct: 100, UpdatedAt: time.Now().UTC()}, "done")
	_ = s.Update(id, func(r *Record) error { r.Status = "READY"; return nil })
	b.log(s, id, "template READY")
}

// progress persists build.json and appends a log line.
func (b *Builder) progress(s *Store, id string, st BuildStatus, note string) {
	dir, err := buildDir(s, id)
	if err != nil {
		return
	}
	if tail := readTail(filepath.Join(dir, "build.log"), 4096); tail != "" {
		st.LogTail = tail
	}
	_ = fsjson.Write(filepath.Join(dir, "build.json"), st)
	b.log(s, id, "phase="+st.Phase+" pct="+fmt.Sprint(st.Pct)+" "+note)
}

func (b *Builder) log(s *Store, id, line string) {
	dir, err := buildDir(s, id)
	if err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "build.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", time.Now().UTC().Format(time.RFC3339), line)
}

func readTail(path string, n int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return ""
	}
	if fi.Size() > int64(n) {
		if _, err := f.Seek(fi.Size()-int64(n), 0); err != nil {
			return ""
		}
	}
	buf := make([]byte, n)
	got, _ := f.Read(buf)
	return string(buf[:got])
}
