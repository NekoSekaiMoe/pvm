package audit

import (
	"strings"
	"testing"
)

// TestRedactSecrets_Patterns is table-driven over every credential shape the
// redactor must mask, plus benign text that must survive untouched.
func TestRedactSecrets_Patterns(t *testing.T) {
	ghp := "ghp_" + strings.Repeat("A", 40)
	akia := "AKIA" + strings.Repeat("B", 16)
	xox := "xoxb-" + strings.Repeat("1234567890-", 2) + "Z"
	bearer := "Bearer " + strings.Repeat("t", 30)

	cases := []struct {
		name  string
		in    string
		want  string // expected output; "" means "unchanged"
		plant string // substring that MUST NOT survive
	}{
		{name: "github token", in: "push failed for " + ghp, plant: ghp},
		{name: "aws key id", in: "credential " + akia + " expired", plant: akia},
		{name: "slack token", in: "post as " + xox, plant: xox},
		{name: "bearer", in: "401 on Authorization: " + bearer, plant: bearer},
		{name: "url query token", in: "upstream 500 https://h.example.com/x?token=" + ghp + "&r=1", plant: ghp},
		{name: "url query sig", in: "GET https://cdn.example.com/f?sig=AbCdEf1234567890", plant: "AbCdEf1234567890"},
		{name: "generic password assignment", in: "dial failed password=hunter2hunter2", plant: "hunter2hunter2"},
		{name: "generic api_key assignment", in: "config api_key=abcdef1234567890", plant: "abcdef1234567890"},
		{name: "benign prose", in: "denied by rule: no matching allow rule", want: "denied by rule: no matching allow rule"},
		{name: "benign monkey key substring", in: "monkey=business is fine", want: "monkey=business is fine"},
		{name: "empty", in: "", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactSecrets(tc.in)
			if tc.plant != "" && strings.Contains(got, tc.plant) {
				t.Errorf("plant %q survived redaction in %q", tc.plant, got)
			}
			if tc.plant != "" && !strings.Contains(got, RedactedPlaceholder) {
				t.Errorf("expected %q marker in %q", RedactedPlaceholder, got)
			}
			if tc.want != "" || tc.in == "" {
				if got != tc.want {
					t.Errorf("RedactSecrets(%q) = %q, want %q", tc.in, got, tc.want)
				}
			}
			// Idempotency: a second pass must not change the output.
			if again := RedactSecrets(got); again != got {
				t.Errorf("not idempotent: %q -> %q", got, again)
			}
		})
	}
}

// TestIsSafeSummaryKey pins the denylist posture: conservative contains-match.
func TestIsSafeSummaryKey(t *testing.T) {
	mustDrop := []string{
		"token", "ApiToken", "api_token", "secret", "client_secret",
		"password", "passwd", "apikey", "api_key", "API_KEY",
		"credential", "cookie", "Authorization", "private_key", "keyboard",
	}
	for _, k := range mustDrop {
		if IsSafeSummaryKey(k) {
			t.Errorf("IsSafeSummaryKey(%q) = true; should be DROPPED", k)
		}
	}
	mustPass := []string{"path", "file", "size", "bytes", "status", "stdout", "exit_code", "url"}
	for _, k := range mustPass {
		if !IsSafeSummaryKey(k) {
			t.Errorf("IsSafeSummaryKey(%q) = false; should PASS", k)
		}
	}
}

// TestScrubValue_Recursive covers the structural scrub: secret-named keys
// dropped at any depth, pattern masking in benignly-named values, and the
// map[string]string / []string promotions.
func TestScrubValue_Recursive(t *testing.T) {
	ghp := "ghp_" + strings.Repeat("C", 40)
	in := map[string]interface{}{
		"path":      "/ok",
		"api_token": "LEAK",
		"url":       "https://h/?token=" + ghp,
		"meta": map[string]interface{}{
			"password": "p",
			"note":     "used " + ghp,
		},
		"items": []interface{}{map[string]interface{}{"secret": "s"}, "plain"},
	}
	out := ScrubValue(in).(map[string]interface{})
	if _, leak := out["api_token"]; leak {
		t.Error("secret-named key api_token survived")
	}
	if out["path"] != "/ok" {
		t.Errorf("safe key path lost: %v", out["path"])
	}
	if url, _ := out["url"].(string); strings.Contains(url, ghp) {
		t.Errorf("token in benign url value survived: %q", url)
	}
	meta := out["meta"].(map[string]interface{})
	if _, leak := meta["password"]; leak {
		t.Error("nested password survived")
	}
	if note, _ := meta["note"].(string); strings.Contains(note, ghp) {
		t.Errorf("token in nested note survived: %q", note)
	}
	items := out["items"].([]interface{})
	if m := items[0].(map[string]interface{}); len(m) != 0 {
		t.Errorf("secret key inside slice element survived: %v", m)
	}
	if items[1] != "plain" {
		t.Errorf("plain slice element altered: %v", items[1])
	}

	// map[string]string promotion (rollback records use this concrete type).
	ms := ScrubValue(map[string]string{"snapshot_id": "snap1", "access_token": "LEAK"})
	m, ok := ms.(map[string]interface{})
	if !ok {
		t.Fatalf("map[string]string not promoted: %T", ms)
	}
	if m["snapshot_id"] != "snap1" {
		t.Errorf("safe string value lost: %v", m)
	}
	if _, leak := m["access_token"]; leak {
		t.Error("access_token survived map[string]string scrub")
	}

	// []string promotion (artifact gate file lists use this concrete type).
	ss := ScrubValue([]string{"plan.txt", ghp + ".log"})
	arr, ok := ss.([]interface{})
	if !ok || len(arr) != 2 {
		t.Fatalf("[]string not promoted: %T %v", ss, ss)
	}
	if arr[0] != "plan.txt" {
		t.Errorf("clean file name altered: %v", arr[0])
	}
	if s, _ := arr[1].(string); strings.Contains(s, ghp) {
		t.Errorf("token in file name survived: %q", s)
	}

	// Scalars and nil pass through untouched.
	if got := ScrubValue(42); got != 42 {
		t.Errorf("int scalar altered: %v", got)
	}
	if got := ScrubValue(nil); got != nil {
		t.Errorf("nil altered: %v", got)
	}
}

// TestDefaultRedactor_Record covers RedactRecord end to end, including the
// runtime kill-switch.
func TestDefaultRedactor_Record(t *testing.T) {
	ghp := "ghp_" + strings.Repeat("D", 40)
	rec := &Record{
		Subject: "agent-" + ghp,
		Action:  "tool:http",
		Params:  map[string]interface{}{"token": "LEAK", "url": "https://h/?sig=sigvalue123456"},
		Reason:  "failed with " + ghp,
	}
	DefaultRedactor().RedactRecord(rec)
	if strings.Contains(rec.Subject, ghp) || strings.Contains(rec.Reason, ghp) {
		t.Errorf("free-text fields still carry the plant: %+v", rec)
	}
	params := rec.Params.(map[string]interface{})
	if _, leak := params["token"]; leak {
		t.Error("Params token key survived RedactRecord")
	}
	if url, _ := params["url"].(string); strings.Contains(url, "sigvalue123456") {
		t.Errorf("url query sig survived: %q", url)
	}

	// Kill-switch: disabled redactor must leave the record untouched.
	SetRedactionEnabled(false)
	t.Cleanup(func() { SetRedactionEnabled(true) })
	raw := &Record{Reason: "plaintext " + ghp, Params: map[string]interface{}{"token": "LEAK"}}
	DefaultRedactor().RedactRecord(raw)
	if !strings.Contains(raw.Reason, ghp) {
		t.Error("disabled redactor still masked Reason")
	}
	if _, ok := raw.Params.(map[string]interface{})["token"]; !ok {
		t.Error("disabled redactor still dropped Params keys")
	}
}
