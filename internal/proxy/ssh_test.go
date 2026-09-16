package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/zukhovich/ssh-tun/internal/config"
	"github.com/zukhovich/ssh-tun/internal/i18n"
	"github.com/zukhovich/ssh-tun/internal/logger"
)

func TestLoadPassphraseProtectedPrivateKey(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(privateKey, "test", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPrivateKey(keyPath, false); err == nil {
		t.Fatal("loadPrivateKey() accepted a protected key without interactive authentication")
	}
}

func TestUnknownHostKeyIsAcceptedAndPersisted(t *testing.T) {
	_, hostPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ssh.NewPublicKey(hostPrivateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	knownHostsPath := filepath.Join(t.TempDir(), ".ssh", "known_hosts")
	cfg := config.NewConfig()
	cfg.KnownHostsFile = knownHostsPath
	cfg.InteractiveAuth = true

	originalConfirm := confirmHostKey
	confirmHostKey = func(string, net.Addr, ssh.PublicKey) (bool, error) { return true, nil }
	t.Cleanup(func() { confirmHostKey = originalConfirm })

	callback, err := hostKeyCallback(cfg)
	if err != nil {
		t.Fatal(err)
	}
	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}
	if err := callback("example.com:22", addr, hostKey); err != nil {
		t.Fatalf("first host-key check failed: %v", err)
	}
	contents, err := os.ReadFile(knownHostsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), hostKey.Type()) {
		t.Fatalf("known_hosts does not contain the accepted key: %q", contents)
	}

	confirmHostKey = func(string, net.Addr, ssh.PublicKey) (bool, error) {
		t.Fatal("a persisted host key must not prompt again")
		return false, nil
	}
	callback, err = hostKeyCallback(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := callback("example.com:22", addr, hostKey); err != nil {
		t.Fatalf("persisted host-key check failed: %v", err)
	}
}

func TestChangedHostKeyIsRejectedWithoutPrompt(t *testing.T) {
	_, firstPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	firstKey, err := ssh.NewPublicKey(firstPrivateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	_, changedPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	changedKey, err := ssh.NewPublicKey(changedPrivateKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{"example.com"}, firstKey) + "\n"
	if err := os.WriteFile(knownHostsPath, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.NewConfig()
	cfg.KnownHostsFile = knownHostsPath
	cfg.InteractiveAuth = true

	originalConfirm := confirmHostKey
	confirmHostKey = func(string, net.Addr, ssh.PublicKey) (bool, error) {
		t.Fatal("a changed host key must never prompt for acceptance")
		return false, nil
	}
	t.Cleanup(func() { confirmHostKey = originalConfirm })

	callback, err := hostKeyCallback(cfg)
	if err != nil {
		t.Fatal(err)
	}
	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}
	if err := callback("example.com:22", addr, changedKey); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected host-key mismatch, got %v", err)
	}
}

func TestConnectToHostWithConfiguredKey(t *testing.T) {
	i18n.Init("en")

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	allowedKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	_, hostPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivateKey)
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
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		serverConn, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
		if err != nil {
			serverDone <- err
			return
		}
		defer serverConn.Close()
		go ssh.DiscardRequests(requests)
		for channel := range channels {
			_ = channel.Reject(ssh.UnknownChannelType, "unsupported")
		}
		serverDone <- nil
	}()

	cfg := config.NewConfig()
	cfg.SSHKeyFile = keyPath
	cfg.InsecureHostKey = true
	cfg.InteractiveAuth = false
	cfg.Timeout = 5 * time.Second

	client, err := connectToHost(cfg, logger.NewLogger(false), "alice", listener.Addr().String(), nil)
	if err != nil {
		t.Fatalf("connectToHost() failed: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("client.Close() failed: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("SSH server failed: %v", err)
	}
}

type testAuthError string

func (e testAuthError) Error() string { return string(e) }

const errTestAuthentication = testAuthError("authentication rejected")
