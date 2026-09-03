package tun

import (
	"math"
	"net"
	"testing"

	"github.com/zukhovich/ssh-tun/internal/config"
	"github.com/zukhovich/ssh-tun/internal/logger"
)

func TestIPv4Arithmetic(t *testing.T) {
	got, err := ipAdd(net.ParseIP("10.0.0.255"), 1)
	if err != nil || got.String() != "10.0.1.0" {
		t.Fatalf("ipAdd = %v, %v", got, err)
	}
	if _, err := ipAdd(net.ParseIP("255.255.255.255"), 1); err == nil {
		t.Fatal("expected an overflow error")
	}
	if _, err := ipSub(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")); err == nil {
		t.Fatal("expected a negative-offset error")
	}
	if got, err := ipToUint32(net.ParseIP("255.255.255.255")); err != nil || got != math.MaxUint32 {
		t.Fatalf("ipToUint32 = %d, %v", got, err)
	}
}

func TestNewTunService(t *testing.T) {
	cfg := config.NewConfig()
	service, err := NewTunService(cfg, logger.NewLogger(false), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if service.tunIP != "10.0.0.1" || service.peerIP != "10.0.0.2" || service.prefix != 24 {
		t.Fatalf("incorrect TUN parameters: %+v", service)
	}
}
