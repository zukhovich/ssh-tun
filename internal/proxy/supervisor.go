package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/zukhovich/ssh-tun/internal/config"
	"github.com/zukhovich/ssh-tun/internal/i18n"
	"github.com/zukhovich/ssh-tun/internal/logger"
)

// Supervisor keeps an SSHClient connected for the whole process lifetime.
// Without auto-reconnect it simply proxies the initial connection and waits
// for the channel to close. With auto-reconnect it rebuilds the connection
// (jump hosts included) whenever the SSH channel is lost, so the local
// listeners survive transient network failures.
type Supervisor struct {
	cfg      *config.Config
	log      *logger.Logger
	current  *SSHClient
	mu       sync.RWMutex
	stop     chan struct{}
	stopOnce sync.Once
}

// NewSupervisor establishes the initial SSH connection.
func NewSupervisor(cfg *config.Config, log *logger.Logger) (*Supervisor, error) {
	client, err := NewSSHClient(cfg, log)
	if err != nil {
		return nil, err
	}
	supervisor := &Supervisor{cfg: cfg, log: log, current: client, stop: make(chan struct{})}
	if cfg.AutoReconnect {
		go supervisor.monitor()
	}
	return supervisor, nil
}

// SSH returns the currently active SSH client.
func (s *Supervisor) SSH() *SSHClient {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// Close stops monitoring and closes the active SSH connection.
func (s *Supervisor) Close() error {
	s.stopOnce.Do(func() { close(s.stop) })
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil {
		return nil
	}
	err := s.current.Close()
	s.current = nil
	return err
}

// monitor watches the active SSH channel and reconnects on failure.
func (s *Supervisor) monitor() {
	for {
		client := s.SSH()
		if client == nil {
			return
		}
		if !waitDisconnected(client, s.cfg.KeepAliveInterval, s.stop) {
			return
		}
		s.log.Warnf(i18n.Text("SSH connection lost; reconnecting every %s...", "SSH-соединение потеряно; переподключение каждые %s..."), s.cfg.ReconnectInterval)
		for {
			select {
			case <-s.stop:
				return
			case <-time.After(s.cfg.ReconnectInterval):
			}
			replacement, err := NewSSHClient(s.cfg, s.log)
			if err != nil {
				s.log.Warnf(i18n.Text("SSH reconnect failed: %v", "Не удалось переподключиться по SSH: %v"), err)
				continue
			}
			if err := client.replaceFrom(replacement); err != nil {
				s.log.Warnf(i18n.Text("SSH reconnect failed: %v", "Не удалось переподключиться по SSH: %v"), err)
				continue
			}
			s.log.Info(i18n.Text("SSH connection restored", "SSH-соединение восстановлено"))
			break
		}
	}
}

// waitDisconnected polls the SSH channel until it fails or shutdown starts.
func waitDisconnected(client *SSHClient, interval time.Duration, stop <-chan struct{}) bool {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if !client.keepAlive(minDuration(interval, 5*time.Second)) {
			return true
		}
		select {
		case <-stop:
			return false
		case <-ticker.C:
		}
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// dialContext routes a dial request through the active SSH client.
func (s *Supervisor) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	client := s.SSH()
	if client == nil {
		return nil, errors.New(i18n.Text("SSH client is not ready", "SSH-клиент не готов"))
	}
	return client.DialContext(ctx, network, addr)
}

// String keeps the supervisor describable in diagnostics.
func (s *Supervisor) String() string {
	return fmt.Sprintf("ssh supervisor (auto-reconnect: %v)", s.cfg.AutoReconnect)
}
