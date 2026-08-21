package egress

import (
	"net/http"
	"testing"
)

// TestRuleMatches_Constraints verifies every L7 constraint participates in
// rule matching: host alone is not enough when Method/Path/Scheme/Port are
// set on the rule (regression: decideDomain used to match on host only).
func TestRuleMatches_Constraints(t *testing.T) {
	allow := true
	base := viewFromHTTP(mustReq(t, "POST", "http://api.example.com/v1/run"))

	tests := []struct {
		name string
		rule EgressRule
		want bool
	}{
		{"host only", EgressRule{Host: "api.example.com", Allow: &allow}, true},
		{"method match", EgressRule{Host: "api.example.com", Method: []string{"POST"}, Allow: &allow}, true},
		{"method mismatch", EgressRule{Host: "api.example.com", Method: []string{"GET"}, Allow: &allow}, false},
		{"method any-of", EgressRule{Host: "api.example.com", Method: []string{"GET", "POST"}, Allow: &allow}, true},
		{"path exact", EgressRule{Host: "api.example.com", Path: "/v1/run", Allow: &allow}, true},
		{"path mismatch", EgressRule{Host: "api.example.com", Path: "/v1/other", Allow: &allow}, false},
		{"path glob", EgressRule{Host: "api.example.com", Path: "/v1/*", Allow: &allow}, true},
		{"path glob miss", EgressRule{Host: "api.example.com", Path: "/v2/*", Allow: &allow}, false},
		{"scheme match", EgressRule{Host: "api.example.com", Scheme: "http", Allow: &allow}, true},
		{"scheme mismatch", EgressRule{Host: "api.example.com", Scheme: "https", Allow: &allow}, false},
		{"port match", EgressRule{Host: "api.example.com", Port: 80, Allow: &allow}, true},
		{"port mismatch", EgressRule{Host: "api.example.com", Port: 8080, Allow: &allow}, false},
		{"wrong host", EgressRule{Host: "other.com", Allow: &allow}, false},
		{"sni fallback", EgressRule{SNI: "api.example.com", Allow: &allow}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ruleMatches(tt.rule, base); got != tt.want {
				t.Fatalf("ruleMatches = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDecideDomain_FullMatchWins verifies a POST-only rule does not authorize
// a GET just because the host matches.
func TestDecideDomain_FullMatchWins(t *testing.T) {
	allow := true
	pol := &Policy{Rules: []EgressRule{
		{Name: "write-only", Host: "api.example.com", Method: []string{"POST"}, Allow: &allow},
	}}
	get := viewFromHTTP(mustReq(t, "GET", "http://api.example.com/anything"))
	if d := (&Gateway{}).decideDomain(get, pol); d != DecisionBlock {
		t.Fatalf("GET must not be allowed by a POST-only rule, got %v", d)
	}
	post := viewFromHTTP(mustReq(t, "POST", "http://api.example.com/anything"))
	if d := (&Gateway{}).decideDomain(post, pol); d != DecisionAllow {
		t.Fatalf("POST must be allowed, got %v", d)
	}
}

// TestApplyInject_FirstFullMatchOnly is the credential-mismatch regression:
// the first fully matching rule wins; if it carries no Inject, a LATER,
// broader rule must not inject its secret into this request. The old
// implementation continued the walk and would leak it.
func TestApplyInject_FirstFullMatchOnly(t *testing.T) {
	allow := true
	pol := &Policy{Rules: []EgressRule{
		{Name: "narrow", Host: "api.example.com", Path: "/v1/run", Allow: &allow}, // matches, no inject
		{Name: "broad", Host: "*.example.com", Allow: &allow,
			Inject: &EgressInject{Header: "Authorization", Format: "Bearer ${SECRET}", Secret: "s3cret"}},
	}}

	// Request matches the narrow rule first -> broad rule's secret must NOT
	// be injected.
	req, _ := http.NewRequest("POST", "http://api.example.com/v1/run", nil)
	g := &Gateway{}
	g.ApplyInject(req, viewFromHTTP(req), pol)
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("broader rule leaked its credential: %q", got)
	}

	// A request that only matches the broad rule still gets the injection.
	req2, _ := http.NewRequest("POST", "http://api.example.com/v2/other", nil)
	g.ApplyInject(req2, viewFromHTTP(req2), pol)
	if got := req2.Header.Get("Authorization"); got != "Bearer s3cret" {
		t.Fatalf("broad rule should inject for unmatched-by-narrow request, got %q", got)
	}
}

// TestViewFromConnect ensures CONNECT views carry the CONNECT method and the
// effective port, so path/method-constrained rules cannot authorize tunnels.
func TestViewFromConnect(t *testing.T) {
	req, _ := http.NewRequest("CONNECT", "http://api.example.com:8443", nil)
	v := viewFromConnect(req)
	if v.method != http.MethodConnect || v.scheme != "https" || v.port != "8443" || v.host != "api.example.com" {
		t.Fatalf("unexpected view: %+v", v)
	}
	// A rule requiring a path can never match a CONNECT (path invisible).
	allow := true
	pol := &Policy{Rules: []EgressRule{{Host: "api.example.com", Path: "/v1/*", Allow: &allow}}}
	if d := (&Gateway{}).decideDomain(v, pol); d != DecisionBlock {
		t.Fatalf("path-constrained rule must not authorize a CONNECT, got %v", d)
	}
}
