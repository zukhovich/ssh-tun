package proxy

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/zukhovich/ssh-tun/internal/config"
	"github.com/zukhovich/ssh-tun/internal/logger"
)

func testSOCKS(t *testing.T, request, response []byte, fn func(*SOCKS5OverSSH, net.Conn) error) {
	t.Helper()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	s := &SOCKS5OverSSH{cfg: config.NewConfig(), logger: logger.NewLogger(false)}
	done := make(chan error, 1)
	go func() { done <- fn(s, server) }()
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(response))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(response) {
		t.Fatalf("response = %v, want %v", got, response)
	}
	if err := <-done; response[len(response)-1] != 0xff && err != nil {
		t.Fatal(err)
	}
}

func TestSOCKS5Handshake(t *testing.T) {
	testSOCKS(t, []byte{5, 1, 0}, []byte{5, 0}, func(s *SOCKS5OverSSH, c net.Conn) error { return s.handshake(c) })
	testSOCKS(t, []byte{5, 1, 2}, []byte{5, 0xff}, func(s *SOCKS5OverSSH, c net.Conn) error { return s.handshake(c) })
}

func TestSOCKS5ReadDomainRequest(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		s := &SOCKS5OverSSH{}
		addr, host, err := s.readRequest(server)
		if err != nil || addr != "example.com:80" || host != "example.com" {
			t.Errorf("readRequest = %q, %q, %v", addr, host, err)
		}
		close(done)
	}()
	request := append([]byte{5, 1, 0, 3, 11}, []byte("example.com")...)
	request = append(request, 0, 80)
	_, _ = client.Write(request)
	<-done
}

func TestSOCKS5StartReportsBindError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cfg := config.NewConfig()
	cfg.SocksAddr = listener.Addr().String()
	server, err := NewSOCKS5OverSSH(cfg, logger.NewLogger(false), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	go server.Start()
	if err := server.Ready(); err == nil {
		t.Fatal("expected a bind error")
	}
}
