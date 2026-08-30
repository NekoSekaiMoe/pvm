package api

import (
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/labstack/echo/v4"

	"uml-container/internal/identity"
	"uml-container/internal/metrics"
	"uml-container/internal/state"
)

// identity_api.go exposes the Credential Broker over REST (bucket-2 gap: the
// WebUI identity page and SDKs previously had no server surface). The broker
// is process-global with durable key + revocation files under the state root,
// so tokens and revocations survive restarts.

var (
	globalIdentityMu   sync.RWMutex
	globalIdentity     *identity.Broker
	globalIdentityRoot string

	metricTokensMinted  = metrics.Counter("pvm_identity_tokens_minted_total", "Credential tokens minted", "task")
	metricTokensRevoked = metrics.Counter("pvm_identity_tokens_revoked_total", "Credential tokens revoked", "task")
)

// CurrentIdentity lazily constructs the global broker with persistence.
// The cache is keyed to the CURRENT state root: tests swap PVM_STATE_ROOT
// (and state.RootDir) between cases, and a stale broker would read/write
// key files in a deleted temp dir.
func CurrentIdentity() (*identity.Broker, error) {
	globalIdentityMu.RLock()
	b, cachedRoot := globalIdentity, globalIdentityRoot
	globalIdentityMu.RUnlock()
	if b != nil && cachedRoot == state.RootDir {
		return b, nil
	}
	globalIdentityMu.Lock()
	defer globalIdentityMu.Unlock()
	if globalIdentity != nil {
		return globalIdentity, nil
	}
	keyPath := filepath.Join(state.RootDir, "identity.key")
	revPath := filepath.Join(state.RootDir, "identity-revocations.json")
	key, err := identity.LoadOrCreateKey(keyPath)
	if err != nil {
		return nil, err
	}
	b, err = identity.NewBroker(key, identity.StaticStore{}, nil, 15*time.Minute)
	if err != nil {
		return nil, err
	}
	if err := b.PersistRevocations(revPath); err != nil {
		// Durable revocation is a hardening feature; degrade to memory.
		os.Stderr.WriteString("identity: revocation persistence disabled: " + err.Error() + "\n")
	}
	globalIdentity = b
	globalIdentityRoot = state.RootDir
	return b, nil
}

// RegisterIdentityManager lets the controller inject its own broker.
func RegisterIdentityManager(b *identity.Broker) {
	globalIdentityMu.Lock()
	globalIdentity = b
	globalIdentityMu.Unlock()
}

func parseTTL(raw string, def time.Duration) time.Duration {
	if raw == "" {
		return def
	}
	if d, err := time.ParseDuration(raw); err == nil && d > 0 {
		return d
	}
	return def
}

// registerIdentityAPI wires the identity endpoints.
func registerIdentityAPI(api *echo.Group) {
	api.POST("/identity/:task/tokens", func(c echo.Context) error {
		task := c.Param("task")
		var req struct {
			Scopes []string `json:"scopes"`
			TTL    string   `json:"ttl"`
			Caller string   `json:"caller"`
			Tenant string   `json:"tenant"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		if len(req.Scopes) == 0 {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "scopes required"})
		}
		if req.Caller == "" {
			req.Caller = "api-user"
		}
		b, err := CurrentIdentity()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		ttl := parseTTL(req.TTL, 15*time.Minute)
		tok, err := b.Mint(req.Caller, req.Tenant, task, req.Scopes, ttl)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		metricTokensMinted.Inc(task)
		return c.JSON(http.StatusOK, map[string]interface{}{
			"token":      tok,
			"expires_at": time.Now().Add(ttl).UTC().Format(time.RFC3339),
			"ttl":        ttl.String(),
		})
	})

	api.POST("/identity/refresh", func(c echo.Context) error {
		var req struct {
			Token string `json:"token"`
			TTL   string `json:"ttl"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		b, err := CurrentIdentity()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		fresh, err := b.Refresh(req.Token, parseTTL(req.TTL, 15*time.Minute))
		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusOK, map[string]string{"token": fresh})
	})

	api.POST("/identity/:task/revoke", func(c echo.Context) error {
		task := c.Param("task")
		var req struct {
			Token string `json:"token"`
			All   bool   `json:"all"`
		}
		if err := c.Bind(&req); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		b, err := CurrentIdentity()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		n := 0
		if req.All {
			n = b.RevokeAllForTask(task)
		} else if req.Token != "" {
			if tok, verr := b.Validate(req.Token); verr == nil {
				b.Revoke(tok.ID)
				n = 1
			} else {
				return c.JSON(http.StatusConflict, map[string]string{"error": verr.Error()})
			}
		} else {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "token or all:true required"})
		}
		metricTokensRevoked.Add(float64(n), task)
		return c.JSON(http.StatusOK, map[string]interface{}{"revoked": n})
	})
}
