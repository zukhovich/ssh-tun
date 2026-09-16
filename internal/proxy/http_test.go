package proxy

import (
	"net"
	"testing"

	"github.com/zukhovich/ssh-tun/internal/config"
	"github.com/zukhovich/ssh-tun/internal/logger"
)

func TestHTTPStartReportsBindError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cfg := config.NewConfig()
	cfg.ListenAddr = listener.Addr().String()
	server, err := NewHTTPOverSSH(cfg, logger.NewLogger(false), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	go server.Start()
	if err := server.Ready(); err == nil {
		t.Fatal("expected a bind error")
	}
}
