package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func startTestSSH(t *testing.T) (string, *ssh.ClientConfig, *queryServer) {
	t.Helper()
	signer, err := hostSigner(filepath.Join(t.TempDir(), "host-key"))
	if err != nil {
		t.Fatal(err)
	}
	s := newQueryServer(signer, basicFetch)
	s.dnsbl = false
	s.cooldown = 0
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.serve(ctx, listener, 8) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("server did not shut down")
		}
	})
	config := &ssh.ClientConfig{User: "check", HostKeyCallback: ssh.FixedHostKey(signer.PublicKey()), Timeout: 3 * time.Second}
	return listener.Addr().String(), config, s
}
func sshClient(t *testing.T) *ssh.Client {
	t.Helper()
	address, config, _ := startTestSSH(t)
	client, err := ssh.Dial("tcp", address, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}
func TestSSHInteractiveSession(t *testing.T) {
	for _, pty := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "pty"}[pty], func(t *testing.T) {
			client := sshClient(t)
			session, err := client.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			var out bytes.Buffer
			session.Stdout = &out
			session.Stderr = io.Discard
			input := "1.1.1.1\n"
			if pty {
				input = "1.1.1.1\r"
				if err = session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
					t.Fatal(err)
				}
			}
			session.Stdin = strings.NewReader(input)
			if err = session.Shell(); err != nil {
				t.Fatal(err)
			}
			if err = session.Wait(); err != nil {
				t.Fatal(err, out.String())
			}
			if !strings.Contains(out.String(), "IP: 1.1.1.1 (IPv4)") {
				t.Fatal(out.String())
			}
		})
	}
}
func TestSSHEnterUsesClientSourceNeverServerDiscovery(t *testing.T) {
	client := sshClient(t)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	var out bytes.Buffer
	session.Stdout = &out
	session.Stdin = strings.NewReader("\n")
	if err = session.Shell(); err != nil {
		t.Fatal(err)
	}
	err = session.Wait()
	var exitErr *ssh.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitStatus() != 1 {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "IP: 127.0.0.1 (IPv4)") {
		t.Fatal("did not use actual SSH source", out.String())
	}
}
func TestServerPromptPublicSource(t *testing.T) {
	s := &queryServer{fetch: basicFetch, lastQuery: map[string]time.Time{}}
	var out bytes.Buffer
	code := s.prompt(context.Background(), netip.MustParseAddr("1.1.1.1"), func() (string, error) { return "", nil }, &out)
	if code != 0 || !strings.Contains(out.String(), "IP: 1.1.1.1") {
		t.Fatal(code, out.String())
	}
}
func TestSSHRejectsSystemAccess(t *testing.T) {
	for _, request := range []string{"exec", "subsystem", "agent", "forward"} {
		t.Run(request, func(t *testing.T) {
			client := sshClient(t)
			if request == "forward" {
				conn, err := client.Dial("tcp", "127.0.0.1:22")
				if err == nil {
					conn.Close()
					t.Fatal("port forwarding accepted")
				}
				return
			}
			session, err := client.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			switch request {
			case "exec":
				if session.Run("whoami") == nil {
					t.Fatal("system command accepted")
				}
			case "subsystem":
				if session.RequestSubsystem("sftp") == nil {
					t.Fatal("SFTP accepted")
				}
			case "agent":
				ok, err := session.SendRequest("auth-agent-req@openssh.com", true, nil)
				if err != nil || ok {
					t.Fatal("agent request accepted", err)
				}
			}
		})
	}
}
func TestSSHOnlyCheckUser(t *testing.T) {
	address, config, _ := startTestSSH(t)
	config.User = "root"
	client, err := ssh.Dial("tcp", address, config)
	if err == nil {
		client.Close()
		t.Fatal("accepted another username")
	}
}
func TestHostKeyPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host-key")
	one, err := hostSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	two, err := hostSigner(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(one.PublicKey().Marshal(), two.PublicKey().Marshal()) {
		t.Fatal("host identity changed")
	}
}
func TestSourceRateLimit(t *testing.T) {
	s := &queryServer{cooldown: time.Minute, lastQuery: map[string]time.Time{}}
	if !s.allowed(netip.MustParseAddr("1.1.1.1")) || s.allowed(netip.MustParseAddr("1.1.1.1")) || !s.allowed(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("source limits failed")
	}
}
