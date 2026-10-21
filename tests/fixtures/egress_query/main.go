// Exercise DNS learning and the real HTTP egress gateway without a guest kernel.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"uml-container/internal/network/egress"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var policy struct {
		Task         string   `json:"task"`
		DNSAddr      string   `json:"dns_addr"`
		AllowDomains []string `json:"allow_domains"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&policy); err != nil {
		return err
	}
	// Query the task's actual DNS proxy so the learned-entry assertion
	// exercises ProcessResponse's allowlist guard, rather than an idle table.
	name, err := dnsmessage.NewName("evil.example.")
	if err != nil {
		return err
	}
	query, err := (&dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 1234, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}).Pack()
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("udp", policy.DNSAddr, 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write(query); err != nil {
		return err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	var response dnsmessage.Message
	if err := response.Unpack(buf[:n]); err != nil {
		return err
	}
	if response.ID != 1234 || !response.Response || response.RCode != dnsmessage.RCodeSuccess || len(response.Answers) == 0 {
		return fmt.Errorf("evil.example DNS query did not receive a successful answer")
	}

	// DNS is transparent; outbound HTTP is rejected by the L7 policy.
	gateway := egress.NewGateway()
	gateway.SetPolicy(policy.Task, &egress.Policy{AllowDomains: policy.AllowDomains})
	listener, err := gateway.ListenForTask(nil, policy.Task)
	if err != nil {
		return err
	}
	defer listener.Close()
	proxy, err := url.Parse("http://" + listener.Addr())
	if err != nil {
		return err
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	resp, err := client.Get("http://evil.example/")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		return fmt.Errorf("egress policy must reject evil.example with 403, got %d", resp.StatusCode)
	}
	return nil
}
