package dnslearn

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// recWriter records map writes (and can be told to fail) so tests observe
// exactly what the learner pushed into the (fake) whitelist map.
type recWriter struct {
	mu      sync.Mutex
	added   map[string]int
	deleted map[string]int
	failErr error
}

func newRecWriter() *recWriter {
	return &recWriter{added: map[string]int{}, deleted: map[string]int{}}
}

func (w *recWriter) AddWhitelist(ip string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failErr != nil {
		return w.failErr
	}
	w.added[ip]++
	return nil
}

func (w *recWriter) DeleteWhitelist(ip string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failErr != nil {
		return w.failErr
	}
	w.deleted[ip]++
	return nil
}

func (w *recWriter) has(ip string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.added[ip] > w.deleted[ip]
}

func testLearner(t *testing.T, cfg Config) *Learner {
	t.Helper()
	if cfg.TaskID == "" {
		cfg.TaskID = "tk-test"
	}
	if cfg.Writer == nil {
		cfg.Writer = newRecWriter()
	}
	l, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func TestLearner_MatchingSemantics(t *testing.T) {
	l := testLearner(t, Config{
		AllowDomains: []string{"example.com", "*.example.org"},
	})
	pub := net.ParseIP("93.184.216.34")

	cases := []struct {
		qname string
		want  int
	}{
		{"example.com", 1},         // exact
		{"EXAMPLE.com.", 1},        // case + trailing dot normalize
		{"api.example.org", 1},     // wildcard subdomain
		{"example.org", 0},         // wildcard does not match the bare suffix
		{"evil-example.com", 0},    // not a suffix of the wildcard rule
		{"notexample.com", 0},      // substring is not a match
		{"example.com.evil.io", 0}, // anchored at the end
	}
	for _, tc := range cases {
		if got := l.ProcessResponse(tc.qname, []net.IP{pub}, 60); got != tc.want {
			t.Errorf("ProcessResponse(%q) learned %d, want %d", tc.qname, got, tc.want)
		}
	}
}

func TestLearner_PublicIPFilter(t *testing.T) {
	w := newRecWriter()
	l := testLearner(t, Config{
		AllowDomains: []string{"example.com"},
		Writer:       w,
	})
	ips := []net.IP{
		net.ParseIP("93.184.216.34"), // public: learned
		net.ParseIP("10.0.0.5"),      // RFC1918
		net.ParseIP("192.168.1.1"),   // RFC1918
		net.ParseIP("172.16.0.9"),    // RFC1918
		net.ParseIP("127.0.0.1"),     // loopback
		net.ParseIP("169.254.1.1"),   // link-local
		net.ParseIP("100.64.0.1"),    // CGNAT
		net.ParseIP("224.0.0.1"),     // multicast
		net.ParseIP("0.0.0.0"),       // unspecified
		net.ParseIP("2001:db8::1"),   // IPv6: out of scope (v4-only map)
	}
	if got := l.ProcessResponse("example.com", ips, 60); got != 1 {
		t.Fatalf("learned %d, want 1 (only the public IPv4)", got)
	}
	if !w.has("93.184.216.34") || w.has("10.0.0.5") || w.has("100.64.0.1") {
		t.Fatalf("writer saw wrong set: added=%v deleted=%v", w.added, w.deleted)
	}
	if got := len(l.LearnedIPs("example.com")); got != 1 {
		t.Fatalf("LearnedIPs = %d, want 1", got)
	}
}

func TestLearner_TTLCappedAndZeroSkipped(t *testing.T) {
	now := time.Now()
	l := testLearner(t, Config{
		AllowDomains: []string{"example.com"},
		LearnTTL:     5 * time.Second,
	})
	l.now = func() time.Time { return now }

	// DNS TTL 1h must be capped to learn_ttl=5s.
	l.ProcessResponse("example.com", []net.IP{net.ParseIP("93.184.216.34")}, 3600)
	es := l.List()
	if len(es) != 1 {
		t.Fatalf("List = %v, want 1 entry", es)
	}
	if es[0].Expiry != now.Add(5*time.Second) {
		t.Fatalf("expiry %v, want capped %v", es[0].Expiry, now.Add(5*time.Second))
	}
	// TTL 0 = "do not cache".
	if got := l.ProcessResponse("example.com", []net.IP{net.ParseIP("93.184.216.35")}, 0); got != 0 {
		t.Fatalf("TTL 0 learned %d, want 0", got)
	}
}

func TestLearner_SweeperExpiry(t *testing.T) {
	w := newRecWriter()
	now := time.Now()
	l := testLearner(t, Config{
		AllowDomains: []string{"example.com"},
		Writer:       w,
	})
	l.now = func() time.Time { return now }

	l.ProcessResponse("example.com", []net.IP{net.ParseIP("93.184.216.34")}, 30)
	if l.Count() != 1 {
		t.Fatalf("count = %d, want 1", l.Count())
	}
	now = now.Add(31 * time.Second) // past expiry
	l.sweep()
	if l.Count() != 0 {
		t.Fatalf("count after sweep = %d, want 0", l.Count())
	}
	if !w.has("93.184.216.34") == (w.deleted["93.184.216.34"] == 1) {
		// added once, deleted once
	}
	if w.deleted["93.184.216.34"] != 1 {
		t.Fatalf("expired entry not deleted from map: %v", w.deleted)
	}
	if got := len(l.LearnedIPs("example.com")); got != 0 {
		t.Fatalf("LearnedIPs after expiry = %d, want 0", got)
	}
}

func TestLearner_MapWriteFailureTolerated(t *testing.T) {
	w := newRecWriter()
	w.failErr = fmt.Errorf("bpffs gone")
	l := testLearner(t, Config{
		AllowDomains: []string{"example.com"},
		Writer:       w,
	})
	// Table insert must succeed even though every map write fails.
	if got := l.ProcessResponse("example.com", []net.IP{net.ParseIP("93.184.216.34")}, 60); got != 1 {
		t.Fatalf("learned %d, want 1 despite map failure", got)
	}
	if l.Count() != 1 {
		t.Fatalf("count = %d, want 1", l.Count())
	}
	// Sweep must not panic either.
	l.sweep()
}

func TestLearner_MaxEntriesCap(t *testing.T) {
	l := testLearner(t, Config{
		AllowDomains: []string{"example.com"},
		MaxEntries:   2,
	})
	ips := []net.IP{
		net.ParseIP("93.184.216.1"),
		net.ParseIP("93.184.216.2"),
		net.ParseIP("93.184.216.3"), // refused: cap reached
	}
	if got := l.ProcessResponse("example.com", ips, 60); got != 2 {
		t.Fatalf("learned %d, want 2 (cap)", got)
	}
	if l.Dropped() != 1 {
		t.Fatalf("dropped = %d, want 1", l.Dropped())
	}
	if l.Count() != 2 {
		t.Fatalf("count = %d, want 2", l.Count())
	}
}

func TestLearner_RefreshDedupes(t *testing.T) {
	l := testLearner(t, Config{AllowDomains: []string{"example.com"}})
	ip := net.ParseIP("93.184.216.34")
	l.ProcessResponse("example.com", []net.IP{ip}, 60)
	l.ProcessResponse("example.com", []net.IP{ip}, 60) // refresh, not duplicate
	if l.Count() != 1 {
		t.Fatalf("count = %d, want 1 (refresh dedupes)", l.Count())
	}
}

func TestLearner_DisabledIsTransparentNoop(t *testing.T) {
	l := testLearner(t, Config{AllowDomains: []string{"example.com"}})
	l.SetEnabled(false)
	if got := l.ProcessResponse("example.com", []net.IP{net.ParseIP("93.184.216.34")}, 60); got != 0 {
		t.Fatalf("disabled learner learned %d, want 0", got)
	}
}

func TestLearner_Drop(t *testing.T) {
	w := newRecWriter()
	l := testLearner(t, Config{AllowDomains: []string{"example.com"}, Writer: w})
	l.ProcessResponse("example.com", []net.IP{
		net.ParseIP("93.184.216.1"), net.ParseIP("93.184.216.2"),
	}, 60)
	if n := l.Drop("example.com"); n != 2 {
		t.Fatalf("dropped %d, want 2", n)
	}
	if l.Count() != 0 || len(l.LearnedIPs("example.com")) != 0 {
		t.Fatalf("entries survived Drop")
	}
	for _, ip := range []string{"93.184.216.1", "93.184.216.2"} {
		if w.deleted[ip] != 1 {
			t.Fatalf("map delete missing for %s: %v", ip, w.deleted)
		}
	}
}

func TestLearner_PerTaskIsolation(t *testing.T) {
	a := testLearner(t, Config{TaskID: "tk-iso-a", AllowDomains: []string{"a.example.com"}})
	b := testLearner(t, Config{TaskID: "tk-iso-b", AllowDomains: []string{"b.example.com"}})
	Register(a)
	Register(b)
	t.Cleanup(func() { Unregister("tk-iso-a", a); Unregister("tk-iso-b", b) })

	a.ProcessResponse("a.example.com", []net.IP{net.ParseIP("93.184.216.1")}, 60)
	// b's allowlist does not cover a.example.com — never inserts.
	b.ProcessResponse("a.example.com", []net.IP{net.ParseIP("93.184.216.2")}, 60)

	c := Checker{}
	if got := c.LearnedIPs("tk-iso-a", "a.example.com"); len(got) != 1 {
		t.Fatalf("task a learned %v, want 1 ip", got)
	}
	if got := c.LearnedIPs("tk-iso-b", "a.example.com"); len(got) != 0 {
		t.Fatalf("task b must not see task a's name, got %v", got)
	}
	if got := c.LearnedIPs("tk-ghost", "a.example.com"); got != nil {
		t.Fatalf("unregistered task must yield nil, got %v", got)
	}
	// Unregister is identity-checked: a stale teardown cannot evict a newer learner.
	Unregister("tk-iso-a", b)
	if For("tk-iso-a") != a {
		t.Fatal("Unregister with the wrong learner evicted the live one")
	}
}

func TestNormalizeUpstream(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1.1.1.1", "1.1.1.1:53"},
		{"1.1.1.1:5353", "1.1.1.1:5353"},
		{"::1", "[::1]:53"},
	}
	for _, tc := range cases {
		got, err := normalizeUpstream(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("normalizeUpstream(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	if _, err := normalizeUpstream("dns.google"); err == nil {
		t.Error("hostname upstream must be rejected")
	}
}

// --- wire-format + proxy end-to-end ---------------------------------------

// buildAResponse crafts a DNS response for query with the given A answers.
func buildAResponse(t *testing.T, query []byte, ttl uint32, ips ...net.IP) []byte {
	t.Helper()
	var parser dnsmessage.Parser
	hdr, err := parser.Start(query)
	if err != nil {
		t.Fatalf("parse query header: %v", err)
	}
	q, err := parser.Question()
	if err != nil {
		t.Fatalf("parse query question: %v", err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: hdr.ID, Response: true, RecursionDesired: true, RecursionAvailable: true,
	})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(q); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	for _, ip := range ips {
		var a dnsmessage.AResource
		copy(a.A[:], ip.To4())
		if err := b.AResource(dnsmessage.ResourceHeader{
			Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl,
		}, a); err != nil {
			t.Fatal(err)
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// buildQuery crafts a minimal A-record query for domain with a fixed id.
func buildQuery(t *testing.T, domain string) []byte {
	t.Helper()
	name, err := dnsmessage.NewName(domain + ".")
	if err != nil {
		t.Fatal(err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{
		Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// fakeResolver is a UDP "upstream" that answers every A query with ips/ttl.
type fakeResolver struct {
	conn *net.UDPConn
	ttl  uint32
	ips  []net.IP
	done chan struct{}
}

func startFakeResolver(t *testing.T, ttl uint32, ips ...net.IP) *fakeResolver {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("fake resolver bind: %v", err)
	}
	f := &fakeResolver{conn: conn, ttl: ttl, ips: ips, done: make(chan struct{})}
	go func() {
		defer close(f.done)
		for {
			buf := make([]byte, dnsProxyBufferSize)
			n, client, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			conn.WriteToUDP(buildAResponse(t, buf[:n], f.ttl, f.ips...), client)
		}
	}()
	t.Cleanup(func() { conn.Close(); <-f.done })
	return f
}

func (f *fakeResolver) addr() string { return f.conn.LocalAddr().String() }

func TestProxy_SnoopsUpstreamResponses(t *testing.T) {
	up := startFakeResolver(t, 60, net.ParseIP("93.184.216.34"))
	l := testLearner(t, Config{
		AllowDomains: []string{"example.com"},
		Upstream:     up.addr(),
	})
	bind, err := l.StartProxy(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatalf("StartProxy: %v", err)
	}
	l.Run(context.Background())

	// A guest-side stub resolver sends a plain A query to the proxy.
	conn, err := net.Dial("udp", bind)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	query := buildQuery(t, "example.com")
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, dnsProxyBufferSize)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no relayed response: %v", err)
	}
	resp := buf[:n]
	if binary.BigEndian.Uint16(resp[:2]) != 0x1234 {
		t.Fatal("relayed response has wrong query id")
	}
	// The response was snooped: the learner must hold the A record now.
	deadline := time.Now().Add(2 * time.Second)
	for len(l.LearnedIPs("example.com")) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	got := l.LearnedIPs("example.com")
	if len(got) != 1 || got[0].String() != "93.184.216.34" {
		t.Fatalf("LearnedIPs = %v, want [93.184.216.34]", got)
	}

	// A non-allowlisted name relays fine but is NEVER learned.
	if _, err := conn.Write(buildQuery(t, "evil.io")); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("non-allowlisted query not relayed: %v", err)
	}
	time.Sleep(50 * time.Millisecond) // let forward() finish snooping
	if got := l.LearnedIPs("evil.io"); len(got) != 0 {
		t.Fatalf("non-allowlisted domain learned: %v", got)
	}
}

func TestProxy_DegradedBindFallback(t *testing.T) {
	l := testLearner(t, Config{AllowDomains: []string{"example.com"}})
	// 192.0.2.1 (TEST-NET-1) is not a local address: the bind fails without
	// root tricks, exercising the degraded fallback.
	bind, err := l.StartProxy(context.Background(), "192.0.2.1:53")
	if err != nil {
		t.Skipf("environment unexpectedly binds 192.0.2.1: %v", err)
	}
	if !strings.HasPrefix(bind, "127.0.0.1:") {
		t.Fatalf("fallback bind = %q, want 127.0.0.1:*", bind)
	}
	if l.Addr() != bind {
		t.Fatalf("Addr() = %q, want %q", l.Addr(), bind)
	}
}

func TestLearnNow(t *testing.T) {
	up := startFakeResolver(t, 120, net.ParseIP("93.184.216.34"))
	l := testLearner(t, Config{Upstream: up.addr()})

	// Not allowlisted: refuses BEFORE touching the network.
	if _, err := l.LearnNow("nope.io"); err == nil {
		t.Fatal("LearnNow on non-allowlisted domain must fail")
	}

	l.AddAllow("promoted.example.com")
	n, err := l.LearnNow("promoted.example.com")
	if err != nil {
		t.Fatalf("LearnNow: %v", err)
	}
	if n != 1 {
		t.Fatalf("LearnNow learned %d, want 1", n)
	}
	if got := l.LearnedIPs("promoted.example.com"); len(got) != 1 {
		t.Fatalf("LearnedIPs = %v", got)
	}
	// Second AddAllow is a no-op.
	if l.AddAllow("promoted.example.com") {
		t.Fatal("duplicate AddAllow reported a change")
	}
}
