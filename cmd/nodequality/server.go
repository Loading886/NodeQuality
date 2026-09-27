package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type queryServer struct {
	config         *ssh.ServerConfig
	fetch          fetchFunc
	dnsbl          bool
	sessionTimeout time.Duration
	cooldown       time.Duration
	mu             sync.Mutex
	lastQuery      map[string]time.Time
}

func hostSigner(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return ssh.ParsePrivateKey(data)
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, err
	}
	data = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return nil, writeErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return ssh.NewSignerFromKey(private)
}

func newQueryServer(signer ssh.Signer, fetch fetchFunc) *queryServer {
	config := &ssh.ServerConfig{NoClientAuth: true, MaxAuthTries: 1, ServerVersion: "SSH-2.0-NodeQuality",
		NoClientAuthCallback: func(meta ssh.ConnMetadata) (*ssh.Permissions, error) {
			if meta.User() != "check" {
				return nil, errors.New("use the check account")
			}
			return nil, nil
		}}
	config.AddHostKey(signer)
	return &queryServer{config: config, fetch: fetch, dnsbl: true, sessionTimeout: 2 * time.Minute, cooldown: 10 * time.Second, lastQuery: map[string]time.Time{}}
}

// This public account only runs an IP query. It is unrelated to the host's sshd
// and cannot run processes, SFTP, forwarding, agent requests or arbitrary exec.
func (s *queryServer) connection(parent context.Context, raw net.Conn) {
	defer raw.Close()
	ctx, cancel := context.WithTimeout(parent, s.sessionTimeout)
	defer cancel()
	go func() { <-ctx.Done(); raw.Close() }()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	conn, channels, requests, err := ssh.NewServerConn(raw, s.config)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = raw.SetDeadline(time.Now().Add(s.sessionTimeout))
	go ssh.DiscardRequests(requests)
	host, _, err := net.SplitHostPort(raw.RemoteAddr().String())
	if err != nil {
		return
	}
	peer, err := parseIP(host)
	if err != nil {
		return
	}
	used := false
	for incoming := range channels {
		if incoming.ChannelType() != "session" || used {
			_ = incoming.Reject(ssh.Prohibited, "only one IP query session is supported")
			continue
		}
		used = true
		channel, reqs, err := incoming.Accept()
		if err != nil {
			return
		}
		go func() { s.session(ctx, channel, reqs, peer); conn.Close() }()
	}
}

func (s *queryServer) allowed(peer netip.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for key, last := range s.lastQuery {
		if now.Sub(last) > 10*time.Minute {
			delete(s.lastQuery, key)
		}
	}
	key := peer.String()
	last, known := s.lastQuery[key]
	if known && now.Sub(last) < s.cooldown {
		return false
	}
	if !known && len(s.lastQuery) >= 4096 {
		return false
	}
	s.lastQuery[key] = now
	return true
}

type terminalIO struct {
	io.Reader
	io.Writer
}

func (s *queryServer) session(ctx context.Context, ch ssh.Channel, requests <-chan *ssh.Request, peer netip.Addr) {
	defer ch.Close()
	pty := false
	width, height := 80, 24
	for req := range requests {
		switch req.Type {
		case "pty-req":
			var p struct {
				Term                         string
				Columns, Rows, Width, Height uint32
				Modes                        string
			}
			ok := !pty && ssh.Unmarshal(req.Payload, &p) == nil && p.Columns >= 20 && p.Columns <= 500 && p.Rows >= 5 && p.Rows <= 200
			if ok {
				pty = true
				width = int(p.Columns)
				height = int(p.Rows)
			}
			_ = req.Reply(ok, nil)
		case "shell":
			if len(req.Payload) != 0 {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)
			limited := io.LimitReader(ch, 4096)
			var writer io.Writer = ch
			var readLine func() (string, error)
			prompt := "输入你要检测的 IP，直接回车检测本次 SSH 连接的来源公网 IP："
			if pty {
				t := term.NewTerminal(terminalIO{limited, ch}, prompt)
				_ = t.SetSize(width, height)
				writer = t
				readLine = t.ReadLine
			} else {
				reader := bufio.NewReader(limited)
				readLine = func() (string, error) { fmt.Fprint(writer, prompt); return reader.ReadString('\n') }
			}
			go func() {
				for r := range requests {
					_ = r.Reply(false, nil)
				}
			}()
			code := s.prompt(ctx, peer, readLine, writer)
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
			return
		default:
			_ = req.Reply(false, nil)
		}
	}
}

func (s *queryServer) prompt(ctx context.Context, peer netip.Addr, readLine func() (string, error), out io.Writer) int {
	fmt.Fprintln(out, "NodeQuality — IP 质量查询")
	fmt.Fprintf(out, "本次连接来源 IP：%s\n", peer)
	fmt.Fprintln(out, "查询在服务器执行；报告仅通过 SSH 返回，不保存、不生成公开链接。")
	fmt.Fprintln(out, "源代码：https://github.com/Loading886/NodeQuality/tree/ip-quality-only")
	for attempt := 0; attempt < 5; attempt++ {
		line, err := readLine()
		if err != nil {
			return 2
		}
		line = strings.TrimSpace(line)
		target := peer
		if line != "" {
			target, err = parseIP(line)
			if err != nil {
				fmt.Fprintln(out, err)
				continue
			}
		}
		if !s.allowed(peer) {
			fmt.Fprintln(out, "查询过于频繁，请稍后再试。")
			return 1
		}
		fmt.Fprintln(out, "正在查询", target, "…")
		r := collect(ctx, s.fetch, target, "cn", s.dnsbl)
		if ctx.Err() != nil {
			return 130
		}
		fmt.Fprint(out, render(r, false))
		if r.Status == "ok" || r.Status == "partial" {
			return 0
		}
		return 1
	}
	fmt.Fprintln(out, "输入错误次数过多，请重新连接。")
	return 2
}

func (s *queryServer) serve(ctx context.Context, listener net.Listener, maxSessions int) error {
	ctx, cancel := context.WithCancel(ctx)
	defer listener.Close()
	go func() { <-ctx.Done(); listener.Close() }()
	slots := make(chan struct{}, maxSessions)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			wg.Add(1)
			go func() { defer wg.Done(); defer func() { <-slots }(); s.connection(ctx, conn) }()
		default:
			conn.Close()
		}
	}
}

func serverMain(ctx context.Context, args []string, errOut io.Writer) int {
	fs := flag.NewFlagSet("nodequality serve", flag.ContinueOnError)
	fs.SetOutput(errOut)
	listen := fs.String("listen", ":2222", "SSH query listener (separate from administrative SSH)")
	key := fs.String("host-key", "nodequality_host_key", "persistent SSH host private key")
	maxSessions := fs.Int("max-sessions", 8, "maximum simultaneous SSH connections")
	cooldown := fs.Duration("cooldown", 10*time.Second, "minimum delay between queries from one source IP")
	deadline := fs.Duration("session-timeout", 2*time.Minute, "maximum connection duration")
	timeout := fs.Int("request-timeout", 10, "HTTPS query timeout in seconds")
	noDNS := fs.Bool("no-dnsbl", false, "skip DNS blacklist lookups")
	if e := fs.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 || *maxSessions < 1 || *maxSessions > 128 || *cooldown < 0 || *deadline < 10*time.Second || *deadline > 10*time.Minute || *timeout < 1 || *timeout > 60 {
		fmt.Fprintln(errOut, "invalid server options")
		return 2
	}
	signer, e := hostSigner(*key)
	if e != nil {
		fmt.Fprintln(errOut, "Host key:", e)
		return 1
	}
	s := newQueryServer(signer, fetcher(*timeout))
	s.cooldown = *cooldown
	s.sessionTimeout = *deadline
	s.dnsbl = !*noDNS
	listener, e := net.Listen("tcp", *listen)
	if e != nil {
		fmt.Fprintln(errOut, e)
		return 1
	}
	fmt.Fprintln(errOut, "NodeQuality SSH query service:", listener.Addr())
	fmt.Fprintln(errOut, "Host key fingerprint:", ssh.FingerprintSHA256(signer.PublicKey()))
	if e = s.serve(ctx, listener, *maxSessions); e != nil {
		fmt.Fprintln(errOut, e)
		return 1
	}
	return 0
}
