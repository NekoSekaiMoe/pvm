package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"uml-container/internal/metrics"
)

func TestObservabilityHealthVersionNoAuth(t *testing.T) {
	e := echo.New()
	registerObservability(e, []byte("secret"))

	for _, path := range []string{"/healthz", "/version"} {
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", path, rec.Code)
		}
	}
}

func TestObservabilityMetricsAuth(t *testing.T) {
	e := echo.New()
	registerObservability(e, []byte("secret"))
	metrics.Counter("pvm_obs_test_total", "observability test").Inc()

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("metrics without auth must 401, got %d", rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics with auth must 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "pvm_obs_test_total") {
		t.Fatalf("metrics body missing series:\n%s", rec.Body.String())
	}
}

func TestObservabilityMetricsNoAuthOptIn(t *testing.T) {
	t.Setenv("PVM_METRICS_NOAUTH", "1")
	e := echo.New()
	registerObservability(e, []byte("secret"))
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("noauth mode must serve metrics, got %d", rec.Code)
	}
}
