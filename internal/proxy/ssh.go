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
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/zukhovich/ssh-tun/internal/config"
	"github.com/zukhovich/ssh-tun/internal/i18n"
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

// getAuthMethods builds authentication methods from the configuration. The
// returned cleanup function must be called after the SSH handshake finishes.
func getAuthMethods(authCfg *AuthConfig, log *logger.Logger, passwordOnly bool) ([]ssh.AuthMethod, func(), error) {
	var authMethods []ssh.AuthMethod
	var agentConn net.Conn
	cleanup := func() {
		if agentConn != nil {
			_ = agentConn.Close()
		}
	}

	if !passwordOnly {
		// Prefer an explicitly configured private key.
		if authCfg.KeyFile != "" {
			log.Debugf(i18n.Text("Trying the configured SSH private key: %s", "Попытка использовать указанный закрытый SSH-ключ: %s"), authCfg.KeyFile)
			signer, err := loadPrivateKey(authCfg.KeyFile, authCfg.InteractiveAuth)
			if err != nil {
				return nil, cleanup, fmt.Errorf(i18n.Text("failed to load the configured SSH private key: %w", "не удалось загрузить указанный закрытый SSH-ключ: %w"), err)
			}
			authMethods = append(authMethods, ssh.PublicKeys(signer))
		} else {
			// Use SSH_AUTH_SOCK when available. This supports passphrase-protected keys
			// and matches the authentication behavior users expect from OpenSSH.
			if socket := os.Getenv("SSH_AUTH_SOCK"); socket != "" {
				conn, err := net.DialTimeout("unix", socket, 2*time.Second)
				if err != nil {
					log.Debugf(i18n.Text("Skipping unavailable SSH agent %s: %v", "Пропуск недоступного SSH-агента %s: %v"), socket, err)
				} else {
					signers, err := agent.NewClient(conn).Signers()
					if err != nil {
						_ = conn.Close()
						log.Debugf(i18n.Text("Failed to list SSH agent keys: %v", "Не удалось получить ключи SSH-агента: %v"), err)
					} else if len(signers) > 0 {
						agentConn = conn
						log.Debugf(i18n.Text("Added %d key(s) from the SSH agent", "Добавлено ключей из SSH-агента: %d"), len(signers))
						authMethods = append(authMethods, ssh.PublicKeys(signers...))
					} else {
						_ = conn.Close()
					}
				}
			}

			// Also try unencrypted keys from the standard SSH directory.
			home, err := os.UserHomeDir()
			if err != nil {
				log.Debugf(i18n.Text("Cannot determine the home directory for default SSH keys: %v", "Не удалось определить домашний каталог для стандартных SSH-ключей: %v"), err)
			} else {
				keyDir := filepath.Join(home, ".ssh")
				candidateKeys := []string{"id_ed25519", "id_ecdsa", "id_rsa", "id_dsa"}
				for _, name := range candidateKeys {
					keyPath := filepath.Join(keyDir, name)
					signer, err := loadPrivateKey(keyPath, false)
					if err != nil {
						log.Debugf(i18n.Text("Skipping unavailable SSH key %s: %v", "Пропуск недоступного SSH-ключа %s: %v"), keyPath, err)
						continue
					}
					log.Debugf(i18n.Text("Added default SSH key: %s", "Добавлен стандартный SSH-ключ: %s"), keyPath)
					authMethods = append(authMethods, ssh.PublicKeys(signer))
				}
			}
		}
	}

	// Add password authentication when requested.
	if passwordOnly {
		password, err := utils.GetSSHPassword(authCfg.Password, authCfg.InteractiveAuth, authCfg.User, authCfg.ServerAddr)
		if err != nil {
			return nil, cleanup, fmt.Errorf(i18n.Text("failed to get the SSH password: %w", "не удалось получить пароль SSH: %w"), err)
		}
		authMethods = append(authMethods, ssh.Password(password))
	}

	if len(authMethods) == 0 {
		cleanup()
		if passwordOnly {
			return nil, func() {}, errors.New(i18n.Text("no password was configured and interactive authentication is unavailable", "пароль не указан, интерактивная аутентификация недоступна"))
		}
		return nil, func() {}, errors.New(i18n.Text("no SSH private keys were found", "доступные закрытые SSH-ключи не найдены"))
	}
	return authMethods, cleanup, nil
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
			log.Errorf(i18n.Text("Failed to parse SSH jump-host parameters: %v", "Ошибка разбора параметров промежуточного SSH-узла: %v"), err)
			sshClient.Close()
			return nil, err
		}
		if user == "" {
			user = cfg.SSHUser
		}
		addr := net.JoinHostPort(host, port)
		log.Infof(i18n.Text("Connecting to SSH jump host %d/%d: %s", "Подключение к промежуточному SSH-узлу %d/%d: %s"), i+1, len(cfg.JumpHosts), addr)

		var lastClient *ssh.Client
		if len(sshClient.jumpClients) > 0 {
			lastClient = sshClient.jumpClients[len(sshClient.jumpClients)-1]
		}

		client, err := connectToHost(cfg, log, user, addr, lastClient)
		if err != nil {
			log.Errorf(i18n.Text("Failed to connect to SSH jump host %s: %v", "Ошибка подключения к промежуточному SSH-узлу %s: %v"), addr, err)
			sshClient.Close()
			return nil, err
		}
		sshClient.jumpClients = append(sshClient.jumpClients, client)
		log.Infof(i18n.Text("Connected to SSH jump host %d: %s@%s", "Подключено к промежуточному SSH-узлу %d: %s@%s"), i+1, user, addr)
	}

	// Connect to the final target server.
	log.Infof(i18n.Text("Preparing to connect to the target SSH server: %s", "Подготовка к подключению к целевому SSH-серверу: %s"), cfg.SSHServer)
	var lastJumpClient *ssh.Client
	if len(sshClient.jumpClients) > 0 {
		lastJumpClient = sshClient.jumpClients[len(sshClient.jumpClients)-1]
	}

	finalClient, err := connectToHost(cfg, log, cfg.SSHUser, cfg.SSHServer, lastJumpClient)
	if err != nil {
		log.Errorf(i18n.Text("Failed to connect to the target SSH server %s: %v", "Ошибка подключения к целевому SSH-серверу %s: %v"), cfg.SSHServer, err)
		sshClient.Close()
		return nil, err
	}

	sshClient.client = finalClient
	log.Infof(i18n.Text("Connected to the target SSH server: %s", "Подключено к целевому SSH-серверу: %s"), cfg.SSHServer)
	return sshClient, nil
}

// connectToHost connects to a jump host or the final target. All available
// authentication methods are offered in one SSH handshake. Interactive
// password input is lazy, so a successful key never causes a password prompt.
func connectToHost(cfg *config.Config, log *logger.Logger, user, addr string, jumpVia *ssh.Client) (*ssh.Client, error) {
	var auths []ssh.AuthMethod
	keyAuthCfg := &AuthConfig{User: user, ServerAddr: addr, KeyFile: cfg.SSHKeyFile, InteractiveAuth: cfg.InteractiveAuth}
	keyAuths, cleanupKeyAuth, keyErr := getAuthMethods(keyAuthCfg, log, false)
	defer cleanupKeyAuth()
	if keyErr == nil {
		auths = append(auths, keyAuths...)
	} else {
		log.Debugf(i18n.Text("SSH key authentication is unavailable: %v", "Аутентификация по SSH-ключу недоступна: %v"), keyErr)
	}

	if cfg.SSHPassword != "" || cfg.InteractiveAuth {
		var password string
		var passwordErr error
		var passwordOnce sync.Once
		passwordProvider := func() (string, error) {
			passwordOnce.Do(func() {
				password, passwordErr = utils.GetSSHPassword(cfg.SSHPassword, cfg.InteractiveAuth, user, addr)
			})
			return password, passwordErr
		}
		auths = append(auths,
			ssh.PasswordCallback(passwordProvider),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				password, err := passwordProvider()
				if err != nil {
					return nil, err
				}
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			}),
		)
	}

	if len(auths) == 0 {
		if keyErr != nil {
			return nil, keyErr
		}
		return nil, errors.New(i18n.Text("no SSH authentication methods are available", "нет доступных методов SSH-аутентификации"))
	}
	return trySingleConnection(cfg, user, addr, cfg.Timeout, auths, jumpVia)
}

// trySingleConnection connects using the supplied authentication methods.
func hostKeyCallback(cfg *config.Config) (ssh.HostKeyCallback, error) {
	if cfg.InsecureHostKey {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	path, err := knownHostsPath(cfg.KnownHostsFile)
	if err != nil {
		return nil, err
	}
	if err := ensureKnownHostsFile(path); err != nil {
		return nil, err
	}
	callback, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf(i18n.Text("failed to load known_hosts %q: %w", "не удалось загрузить known_hosts %q: %w"), path, err)
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := callback(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) || len(keyErr.Want) != 0 {
			return err
		}
		if !cfg.InteractiveAuth {
			return fmt.Errorf(i18n.Text("SSH host key is unknown; add it to %s or use --insecure-host-key: %w", "ключ SSH-сервера неизвестен; добавьте его в %s или используйте --insecure-host-key: %w"), path, err)
		}
		accepted, promptErr := confirmHostKey(hostname, remote, key)
		if promptErr != nil {
			return promptErr
		}
		if !accepted {
			return errors.New(i18n.Text("SSH host key was not accepted", "ключ SSH-сервера не принят"))
		}
		if err := appendKnownHost(path, hostname, key); err != nil {
			return err
		}
		return nil
	}, nil
}

func knownHostsPath(configured string) (string, error) {
	path := configured
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf(i18n.Text("failed to determine the home directory for known_hosts: %w", "не удалось определить домашний каталог для known_hosts: %w"), err)
		}
		return filepath.Join(home, ".ssh", "known_hosts"), nil
	}
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf(i18n.Text("failed to expand the known_hosts path: %w", "не удалось развернуть путь к known_hosts: %w"), err)
		}
		path = filepath.Join(home, path[2:])
	}
	return path, nil
}

func ensureKnownHostsFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf(i18n.Text("failed to create the known_hosts directory: %w", "не удалось создать каталог known_hosts: %w"), err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf(i18n.Text("failed to create known_hosts %q: %w", "не удалось создать known_hosts %q: %w"), path, err)
	}
	return file.Close()
}

var (
	confirmHostKey   = confirmUnknownHostKey
	knownHostsFileMu sync.Mutex
)

func confirmUnknownHostKey(hostname string, remote net.Addr, key ssh.PublicKey) (bool, error) {
	fmt.Fprintf(os.Stderr, i18n.Text(
		"The authenticity of host '%s' (%s) cannot be established.\n%s key fingerprint is SHA256:%s.\nContinue connecting (yes/no)? ",
		"Подлинность узла '%s' (%s) не установлена.\nОтпечаток ключа %s: SHA256:%s.\nПродолжить подключение (yes/no)? ",
	), knownhosts.Normalize(hostname), remote.String(), key.Type(), ssh.FingerprintSHA256(key)[7:])
	var answer string
	if _, err := fmt.Fscanln(os.Stdin, &answer); err != nil {
		return false, fmt.Errorf(i18n.Text("failed to read host-key confirmation: %w", "не удалось прочитать подтверждение ключа сервера: %w"), err)
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "yes" || answer == "y" || answer == "да" || answer == "д", nil
}

func appendKnownHost(path, hostname string, key ssh.PublicKey) error {
	knownHostsFileMu.Lock()
	defer knownHostsFileMu.Unlock()
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf(i18n.Text("failed to open known_hosts %q: %w", "не удалось открыть known_hosts %q: %w"), path, err)
	}
	defer file.Close()
	address := knownhosts.Normalize(hostname)
	line := knownhosts.Line([]string{knownhosts.HashHostname(address)}, key) + "\n"
	if _, err := file.WriteString(line); err != nil {
		return fmt.Errorf(i18n.Text("failed to save the SSH host key: %w", "не удалось сохранить ключ SSH-сервера: %w"), err)
	}
	return nil
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
		return nil, fmt.Errorf(i18n.Text("failed to connect to %s through an SSH jump host: %w", "не удалось подключиться к %s через промежуточный SSH-узел: %w"), addr, err)
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, fmt.Errorf(i18n.Text("failed to set the SSH connection deadline: %w", "не удалось установить таймаут SSH-соединения: %w"), err)
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf(i18n.Text("failed to establish an SSH connection to %s through a jump host: %w", "не удалось установить SSH-подключение к %s через промежуточный SSH-узел: %w"), addr, err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		c.Close()
		return nil, fmt.Errorf(i18n.Text("failed to clear the SSH connection deadline: %w", "не удалось сбросить таймаут SSH-соединения: %w"), err)
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
		s.logger.Debug(i18n.Text("Closing the target SSH connection", "Закрытие целевого SSH-подключения"))
		if err := s.client.Close(); err != nil {
			errs = append(errs, err)
		}
		s.client = nil
	}
	if s.jumpClients != nil {
		for i := len(s.jumpClients) - 1; i >= 0; i-- {
			if s.jumpClients[i] != nil {
				s.logger.Debugf(i18n.Text("Closing SSH jump-host connection %d", "Закрытие подключения к промежуточному SSH-узлу %d"), i+1)
				if err := s.jumpClients[i].Close(); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	s.jumpClients = nil
	return errors.Join(errs...)
}

func loadPrivateKey(path string, promptForPassphrase bool) (ssh.Signer, error) {
	expanded := path
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf(i18n.Text("failed to expand the ~ path: %w", "не удалось развернуть путь ~: %w"), err)
		}
		expanded = filepath.Join(home, path[2:])
	}

	key, err := os.ReadFile(expanded)
	if err != nil {
		return nil, fmt.Errorf(i18n.Text("failed to read private key file %q: %w", "не удалось прочитать файл закрытого ключа %q: %w"), expanded, err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err == nil {
		return signer, nil
	}
	if _, ok := err.(*ssh.PassphraseMissingError); !ok {
		return nil, fmt.Errorf(i18n.Text("failed to parse private key %q: %w", "не удалось разобрать закрытый ключ %q: %w"), expanded, err)
	}
	if !promptForPassphrase {
		return nil, fmt.Errorf(i18n.Text("private key %q is passphrase-protected; load it into ssh-agent or enable interactive authentication", "закрытый ключ %q защищён парольной фразой; добавьте его в ssh-agent или включите интерактивную аутентификацию"), expanded)
	}
	passphrase, err := utils.ReadPasswordFromTerminal(fmt.Sprintf(
		i18n.Text("Enter passphrase for SSH key %s: ", "Введите парольную фразу для SSH-ключа %s: "),
		expanded,
	))
	if err != nil {
		return nil, err
	}
	signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf(i18n.Text("failed to decrypt private key %q: %w", "не удалось расшифровать закрытый ключ %q: %w"), expanded, err)
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
		return nil, errors.New(i18n.Text("SSH client is not ready", "SSH-клиент не готов"))
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
