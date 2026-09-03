package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/zukhovich/ssh-tun/internal/config"
	"github.com/zukhovich/ssh-tun/internal/logger"
	"github.com/zukhovich/ssh-tun/internal/utils"
)

// SSHClient manages the target and jump-host SSH connections.
type SSHClient struct {
	client      *ssh.Client   // Final target connection.
	jumpClients []*ssh.Client // Intermediate jump-host connections.
	config      *ssh.ClientConfig
	logger      *logger.Logger
	mu          sync.RWMutex
	closed      bool
}

type AuthConfig struct {
	User            string
	Password        string
	KeyFile         string
	ServerAddr      string
	InteractiveAuth bool
}

// getAuthMethods builds authentication methods from the configuration.
func getAuthMethods(authCfg *AuthConfig, log *logger.Logger, passwordOnly bool) ([]ssh.AuthMethod, error) {
	var authMethods []ssh.AuthMethod

	if !passwordOnly {
		// Prefer an explicitly configured private key.
		if authCfg.KeyFile != "" {
			log.Debugf("Попытка использовать указанный SSH-ключ: %s", authCfg.KeyFile)
			signer, err := loadPrivateKey(authCfg.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("не удалось загрузить указанный SSH-ключ: %w", err)
			}
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		} else {
			// Otherwise try keys from the standard SSH directory.
			home, _ := os.UserHomeDir()
			keyDir := filepath.Join(home, ".ssh")
			candidateKeys := []string{"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"}

			for _, name := range candidateKeys {
				keyPath := filepath.Join(keyDir, name)
				signer, err := loadPrivateKey(keyPath)
				if err != nil {
					log.Debugf("Пропуск недоступного ключа %s: %v", keyPath, err)
					continue
				}
				log.Debugf("Найден и добавлен ключ по умолчанию: %s", keyPath)
				authMethods = append(authMethods, ssh.PublicKeys(signer))
			}
		}
	}

	// Add password authentication when requested.
	if passwordOnly {
		password, err := utils.GetSSHPassword(authCfg.Password, authCfg.InteractiveAuth, authCfg.User, authCfg.ServerAddr)
		if err != nil {
			return nil, fmt.Errorf("не удалось получить пароль SSH: %w", err)
		}
		authMethods = append(authMethods, ssh.Password(password))
	}

	if len(authMethods) == 0 {
		if passwordOnly {
			return nil, fmt.Errorf("не указан пароль или интерактивная аутентификация")
		}
		return nil, fmt.Errorf("не найдены доступные SSH-ключи")
	}
	return authMethods, nil
}

func NewSSHClient(cfg *config.Config, log *logger.Logger) (*SSHClient, error) {
	sshClient := &SSHClient{
		logger:      log,
		jumpClients: []*ssh.Client{},
	}

	// Connect to jump hosts in order.
	for i, jumpHostsStr := range cfg.JumpHosts {
		user, host, port, err := cfg.GetJumpHostInfo(jumpHostsStr)
		if err != nil {
			log.Errorf("Ошибка разбора параметров промежуточного SSH-узла: %v", err)
			sshClient.Close()
			return nil, err
		}
		if user == "" {
			user = cfg.SSHUser
		}
		addr := net.JoinHostPort(host, port)
		log.Infof("Подключение к промежуточному SSH-узлу %d/%d: %s", i+1, len(cfg.JumpHosts), addr)

		var lastClient *ssh.Client
		if len(sshClient.jumpClients) > 0 {
			lastClient = sshClient.jumpClients[len(sshClient.jumpClients)-1]
		}

		client, err := connectToHost(cfg, log, user, addr, lastClient)
		if err != nil {
			log.Errorf("Ошибка подключения к промежуточному SSH-узлу %s: %v", addr, err)
			sshClient.Close()
			return nil, err
		}
		sshClient.jumpClients = append(sshClient.jumpClients, client)
		log.Infof("Подключено к промежуточному SSH-узлу %d: %s@%s", i+1, user, addr)
	}

	// Connect to the final target server.
	log.Infof("Подготовка к подключению к целевому серверу: %s", cfg.SSHServer)
	var lastJumpClient *ssh.Client
	if len(sshClient.jumpClients) > 0 {
		lastJumpClient = sshClient.jumpClients[len(sshClient.jumpClients)-1]
	}

	finalClient, err := connectToHost(cfg, log, cfg.SSHUser, cfg.SSHServer, lastJumpClient)
	if err != nil {
		log.Errorf("Ошибка подключения к целевому серверу %s: %v", cfg.SSHServer, err)
		sshClient.Close()
		return nil, err
	}

	sshClient.client = finalClient
	log.Infof("Подключён к целевому серверу: %s", cfg.SSHServer)
	return sshClient, nil
}

// connectToHost connects to a jump host or the final target.
func connectToHost(cfg *config.Config, log *logger.Logger, user, addr string, jumpVia *ssh.Client) (*ssh.Client, error) {
	// Stage 1: key authentication.
	log.Debugf("Этап 1: попытка подключения по ключу к %s", addr)
	keyAuthCfg := &AuthConfig{User: user, ServerAddr: addr, KeyFile: cfg.SSHKeyFile}
	keyAuths, err := getAuthMethods(keyAuthCfg, log, false) // false selects key methods.
	if err == nil && len(keyAuths) > 0 {
		client, err := trySingleConnection(cfg, user, addr, cfg.Timeout, keyAuths, jumpVia)
		if err == nil {
			log.Debugf("Аутентификация по ключу успешна: %s", addr)
			return client, nil
		}
		log.Warnf("Аутентификация по ключу не удалась: %v. Попытка других методов...", err)
	} else if err != nil {
		log.Debugf("Ошибка получения методов с ключами: %v", err)
	}

	// Stage 2: password authentication after key authentication fails.
	if cfg.InteractiveAuth || cfg.SSHPassword != "" {
		log.Debugf("Этап 2: попытка аутентификации по паролю для %s", addr)
		passwordAuthCfg := &AuthConfig{User: user, ServerAddr: addr, Password: cfg.SSHPassword, InteractiveAuth: cfg.InteractiveAuth}
		passwordAuths, err := getAuthMethods(passwordAuthCfg, log, true) // true selects password only.
		if err == nil && len(passwordAuths) > 0 {
			client, err := trySingleConnection(cfg, user, addr, cfg.Timeout, passwordAuths, jumpVia)
			if err == nil {
				log.Debugf("Аутентификация по паролю успешна: %s", addr)
				return client, nil
			}
			log.Warnf("Аутентификация по паролю не удалась: %v", err)
		} else if err != nil {
			log.Debugf("Ошибка получения методов с паролем: %v", err)
		}
	}

	return nil, fmt.Errorf("все методы аутентификации не удались")
}

// trySingleConnection connects using the supplied authentication methods.
func hostKeyCallback(cfg *config.Config) (ssh.HostKeyCallback, error) {
	if cfg.InsecureHostKey {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	path := cfg.KnownHostsFile
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("не удалось определить домашний каталог для known_hosts: %w", err)
		}
		path = filepath.Join(home, ".ssh", "known_hosts")
	} else if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("не удалось развернуть путь к known_hosts: %w", err)
		}
		path = filepath.Join(home, path[2:])
	}
	callback, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("не удалось загрузить known_hosts %q: %w", path, err)
	}
	return callback, nil
}

func trySingleConnection(cfg *config.Config, user, addr string, timeout time.Duration, auths []ssh.AuthMethod, jumpVia *ssh.Client) (*ssh.Client, error) {
	callback, err := hostKeyCallback(cfg)
	if err != nil {
		return nil, err
	}
	sshConfig := &ssh.ClientConfig{
		User:            user,
		Auth:            auths,
		HostKeyCallback: callback,
		Timeout:         timeout,
	}

	if jumpVia == nil {
		// Direct connection.
		return ssh.Dial("tcp", addr, sshConfig)
	}

	// Connection through a jump host.
	conn, err := jumpVia.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("не удалось подключиться к %s через промежуточный SSH-узел: %w", addr, err)
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("не удалось установить таймаут SSH-соединения: %w", err)
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("не удалось установить SSH-подключение к %s через промежуточный SSH-узел: %w", addr, err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		c.Close()
		return nil, fmt.Errorf("не удалось сбросить таймаут SSH-соединения: %w", err)
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// Close closes all SSH connections in reverse order.
func (s *SSHClient) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var errs []error
	if s.client != nil {
		s.logger.Debug("Закрытие целевого SSH-подключения")
		if err := s.client.Close(); err != nil {
			errs = append(errs, err)
		}
		s.client = nil
	}
	if s.jumpClients != nil {
		for i := len(s.jumpClients) - 1; i >= 0; i-- {
			if s.jumpClients[i] != nil {
				s.logger.Debugf("Закрытие подключения к промежуточному SSH-узлу %d", i+1)
				if err := s.jumpClients[i].Close(); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	s.jumpClients = nil
	return errors.Join(errs...)
}

func loadPrivateKey(path string) (ssh.Signer, error) {
	expanded := path
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("не удалось развернуть путь ~: %w", err)
		}
		expanded = filepath.Join(home, path[2:])
	}

	key, err := os.ReadFile(expanded)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать файл ключа '%s': %w", expanded, err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		// Return a clear error for passphrase-protected keys.
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			return nil, fmt.Errorf("ключ '%s' защищён паролем, автоматическая обработка не поддерживается", expanded)
		}
		return nil, fmt.Errorf("не удалось разобрать файл ключа '%s': %w", expanded, err)
	}

	return signer, nil
}

// Dial opens a channel through the target SSH connection.
func (s *SSHClient) Dial(network, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.DialContext(ctx, network, addr)
}

// DialContext closes a late SSH channel when its context is canceled.
func (s *SSHClient) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	s.mu.RLock()
	if s.closed || s.client == nil {
		s.mu.RUnlock()
		return nil, fmt.Errorf("SSH-клиент не готов")
	}
	client := s.client
	s.mu.RUnlock()
	type result struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		conn, err := client.Dial(network, addr)
		resultCh <- result{conn: conn, err: err}
	}()
	select {
	case result := <-resultCh:
		return result.conn, result.err
	case <-ctx.Done():
		go func() {
			result := <-resultCh
			if result.conn != nil {
				result.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}
