package api

import (
	"crypto/subtle"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"uml-container/internal/metrics"
	"uml-container/internal/version"
)

// registerObservability wires /healthz, /version, /metrics and (opt-in)
// /debug/pprof. healthz and version are intentionally UNAUTHENTICATED (they
// leak no state beyond build metadata and liveness, which Docker/compose
// healthchecks and load balancers need before any secret is configured).
// /metrics follows the API auth unless PVM_METRICS_NOAUTH=1 opts out for
// scrapers that cannot send headers. pprof is disabled unless PVM_PPROF=1.
func registerObservability(e *echo.Echo, apiSecretBytes []byte) {
	e.GET("/healthz", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"status":         "ok",
			"uptime_seconds": int(metrics.Uptime().Seconds()),
			"time":           time.Now().UTC().Format(time.RFC3339),
		})
	})

	e.GET("/version", func(c echo.Context) error {
		return c.JSON(http.StatusOK, version.Current())
	})

	metricsHandler := func(c echo.Context) error {
		return c.String(http.StatusOK, metrics.Default().Render())
	}
	if os.Getenv("PVM_METRICS_NOAUTH") == "1" {
		e.GET("/metrics", metricsHandler)
	} else {
		e.GET("/metrics", metricsHandler, metricsAuth(apiSecretBytes))
	}

	if os.Getenv("PVM_PPROF") == "1" {
		debug := e.Group("/debug/pprof")
		wrap := func(h http.HandlerFunc) echo.HandlerFunc {
			return func(c echo.Context) error {
				h(c.Response(), c.Request())
				return nil
			}
		}
		wrapHandler := func(h http.Handler) echo.HandlerFunc {
			return func(c echo.Context) error {
				h.ServeHTTP(c.Response(), c.Request())
				return nil
			}
		}
		debug.GET("", wrap(pprof.Index))
		debug.GET("/", wrap(pprof.Index))
		debug.GET("/heap", wrapHandler(pprof.Handler("heap")))
		debug.GET("/goroutine", wrapHandler(pprof.Handler("goroutine")))
		debug.GET("/block", wrapHandler(pprof.Handler("block")))
		debug.GET("/cmdline", wrap(pprof.Cmdline))
		debug.GET("/profile", wrap(pprof.Profile))
		debug.GET("/symbol", wrap(pprof.Symbol))
		debug.GET("/trace", wrap(pprof.Trace))
	}
}

// metricsAuth mirrors the /api KeyAuth (constant-time bearer compare) without
// depending on middleware ordering.
func metricsAuth(secret []byte) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			key := strings.TrimPrefix(c.Request().Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(key), secret) == 1 {
				return next(c)
			}
			return echo.NewHTTPError(http.StatusUnauthorized, map[string]string{"message": "unauthorized"})
		}
	}
}
