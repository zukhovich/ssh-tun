package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/zukhovich/ssh-tun/internal/config"
	"github.com/zukhovich/ssh-tun/internal/logger"
)

// startTestSSHServer starts a minimal SSH server that accepts one key.
func startTestSSHServer(t *testing.T) (string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	allowedKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(metadata ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if metadata.User() == "alice" && string(key.Marshal()) == string(allowedKey.Marshal()) {
				return nil, nil
			}
			return nil, errTestAuthentication
		},
	}
	serverConfig.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				serverConn, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
				if err != nil {
					conn.Close()
					return
				}
				defer serverConn.Close()
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					_ = channel.Reject(ssh.UnknownChannelType, "unsupported")
				}
			}()
		}
	}()
	return keyPath, listener.Addr().String()
}

func newTestConfig(t *testing.T, addr, keyPath string, reconnect bool) *config.Config {
	t.Helper()
	cfg := config.NewConfig()
	cfg.SSHServer = addr
	cfg.SSHUser = "alice"
	cfg.SSHKeyFile = keyPath
	cfg.InsecureHostKey = true
	cfg.InteractiveAuth = false
	cfg.Timeout = 5 * time.Second
	cfg.AutoReconnect = reconnect
	return cfg
}

func TestSupervisorWithoutReconnect(t *testing.T) {
	keyPath, addr := startTestSSHServer(t)
	cfg := newTestConfig(t, addr, keyPath, false)
	supervisor, err := NewSupervisor(cfg, logger.NewLogger(false))
	if err != nil {
		t.Fatalf("NewSupervisor() failed: %v", err)
	}
	if supervisor.SSH() == nil {
		t.Fatal("expected an active SSH client")
	}
	if err := supervisor.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
}

func TestWaitDisconnectedDetectsClosedChannel(t *testing.T) {
	keyPath, addr := startTestSSHServer(t)
	cfg := newTestConfig(t, addr, keyPath, false)
	supervisor, err := NewSupervisor(cfg, logger.NewLogger(false))
	if err != nil {
		t.Fatal(err)
	}
	client := supervisor.SSH()
	if !client.keepAlive(time.Second) {
		t.Fatal("a healthy channel must answer keepalive probes")
	}
	stop := make(chan struct{})
	healthyDone := make(chan bool, 1)
	go func() { healthyDone <- waitDisconnected(client, 20*time.Millisecond, stop) }()
	time.Sleep(60 * time.Millisecond)
	close(stop)
	if <-healthyDone {
		t.Fatal("a healthy channel must not be reported as disconnected")
	}
	if err := supervisor.Close(); err != nil {
		t.Fatalf("supervisor close failed: %v", err)
	}
	if !client.disconnected() {
		t.Fatal("a closed client must be reported as disconnected")
	}
}
