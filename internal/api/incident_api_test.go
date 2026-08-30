package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"uml-container/internal/network/egress"
	"uml-container/internal/state"
)

func TestIncidentReportAndList(t *testing.T) {
	t.Setenv("PVM_STATE_ROOT", t.TempDir())
	t.Setenv("PVM_CGROUP_ROOT", t.TempDir())

	e := echo.New()
	api := e.Group("/api", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error { return next(c) }
	})
	registerIncidentAPI(api)

	// Invalid severity rejected.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/incidents/t-1/report", strings.NewReader(`{"severity":"apocalyptic"}`))
	req.Header.Set("Content-Type", "application/json")
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid severity must 400, got %d", rec.Code)
	}

	// Valid report: medium => pause branch; hooks degrade (no cgroup dir)
	// but the action is still recorded.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/incidents/t-1/report", strings.NewReader(`{"severity":"medium","kind":"sensor:test","detail":"unit"}`))
	req.Header.Set("Content-Type", "application/json")
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("report must 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Action  string `json:"action"`
		Warning string `json:"warning"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Action != "pause" {
		t.Fatalf("medium severity must classify as pause, got %s", resp.Action)
	}

	// List shows the handled incident.
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/incidents", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list must 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "sensor:test") {
		t.Fatalf("list must contain the incident: %s", rec.Body.String())
	}
}

func TestIncidentEgressDenyAll(t *testing.T) {
	t.Setenv("PVM_STATE_ROOT", t.TempDir())
	// The env var is only resolved at package init; swap the package var so
	// CurrentIdentity/currentIncident rebuild against a live directory.
	state.RootDir = t.TempDir()
	// A registered gateway gets deny-alled by a high-severity incident.
	g := egress.NewGateway()
	RegisterEgressGateway("t-egress", g)
	g.SetPolicy("t-egress", &egress.Policy{AllowDomains: []string{"example.com"}})
	act, err := reportIncident("high", "t-egress", "test:exfil", "unit")
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if act != "quarantine" {
		t.Fatalf("high severity must quarantine, got %s", act)
	}
	if len(g.PolicySnapshot("t-egress").AllowDomains) != 0 {
		t.Fatal("BlockNetwork must leave an empty (deny-all) allowlist")
	}
}
