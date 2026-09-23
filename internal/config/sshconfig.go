package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	sshconfig "github.com/kevinburke/ssh_config"
	"github.com/zukhovich/ssh-tun/internal/i18n"
)

// ResolveSSHConfig applies OpenSSH client configuration for target. Explicit
// ssh-tun command-line/YAML values should be applied after this function.
func ResolveSSHConfig(cfg *Config, target string) error {
	alias, explicitUser, explicitPort, err := splitSSHConfigTarget(target)
	if err != nil {
		return err
	}
	lookupAlias := alias
	settings := &sshconfig.UserSettings{}
	if cfg.SSHConfigFile != "" {
		path, err := expandSSHPath(cfg.SSHConfigFile, alias, explicitUser, lookupAlias)
		if err != nil {
			return err
		}
		settings.ConfigFinder(func() string { return path })
	}
	get := func(key string) (string, error) {
		value, err := settings.GetStrict(lookupAlias, key)
		if err != nil {
			return "", fmt.Errorf(i18n.T("read SSH client configuration: %w"), err)
		}
		return strings.TrimSpace(value), nil
	}

	hostname, err := get("HostName")
	if err != nil {
		return err
	}
	if hostname == "" {
		hostname = alias
	}
	hostname = expandSSHValue(hostname, alias, explicitUser, lookupAlias)
	userName, err := get("User")
	if err != nil {
		return err
	}
	if explicitUser != "" {
		userName = explicitUser
	}
	if userName == "" {
		current, userErr := user.Current()
		if userErr == nil {
			userName = current.Username
		}
	}
	port, err := get("Port")
	if err != nil {
		return err
	}
	if explicitPort != "" {
		port = explicitPort
	}
	if port == "" {
		port = "22"
	}

	cfg.SSHServer = hostname
	cfg.SSHUser = userName
	if cfg.SSHPort == "" || cfg.SSHPort == "22" {
		cfg.SSHPort = port
	}

	identities, err := settings.GetAllStrict(lookupAlias, "IdentityFile")
	if err != nil {
		return fmt.Errorf(i18n.T("read SSH client configuration: %w"), err)
	}
	cfg.SSHKeyFiles = nil
	if len(identities) == 1 && identities[0] == sshconfig.Default("IdentityFile") {
		identities = nil
	}
	for _, identity := range identities {
		identity = strings.TrimSpace(identity)
		if identity == "" || strings.EqualFold(identity, "none") {
			continue
		}
		expanded, err := expandSSHPath(identity, hostname, userName, lookupAlias)
		if err != nil {
			return err
		}
		cfg.SSHKeyFiles = append(cfg.SSHKeyFiles, expanded)
	}

	knownHosts, err := get("UserKnownHostsFile")
	if err != nil {
		return err
	}
	if knownHosts != "" && !strings.EqualFold(knownHosts, "none") {
		fields := strings.Fields(knownHosts)
		if len(fields) > 0 {
			cfg.KnownHostsFile, err = expandSSHPath(fields[0], hostname, userName, lookupAlias)
			if err != nil {
				return err
			}
		}
	}

	proxyJump, err := get("ProxyJump")
	if err != nil {
		return err
	}
	if proxyJump != "" && !strings.EqualFold(proxyJump, "none") {
		cfg.JumpHosts = splitCommaList(proxyJump)
	} else {
		cfg.JumpHosts = nil
	}

	connectTimeout, err := get("ConnectTimeout")
	if err != nil {
		return err
	}
	if connectTimeout != "" && connectTimeout != "0" {
		seconds, parseErr := strconv.Atoi(connectTimeout)
		if parseErr != nil || seconds < 1 {
			return fmt.Errorf(i18n.T("invalid ConnectTimeout in SSH client configuration: %s"), connectTimeout)
		}
		cfg.Timeout = timeSeconds(seconds)
	}
	return nil
}

func splitSSHConfigTarget(target string) (alias, userName, port string, err error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", "", "", errors.New(i18n.T("SSH target is required"))
	}
	if at := strings.LastIndex(target, "@"); at >= 0 {
		if at == 0 || at == len(target)-1 || strings.Contains(target[:at], "@") {
			return "", "", "", errors.New(i18n.T("invalid SSH target; expected [user@]host or an SSH config alias"))
		}
		userName, target = target[:at], target[at+1:]
	}
	if host, parsedPort, splitErr := net.SplitHostPort(target); splitErr == nil {
		target, port = host, parsedPort
	} else if strings.HasPrefix(target, "[") && strings.HasSuffix(target, "]") {
		target = strings.TrimSuffix(strings.TrimPrefix(target, "["), "]")
	} else if strings.Count(target, ":") == 1 {
		host, parsedPort, ok := strings.Cut(target, ":")
		if !ok || host == "" || parsedPort == "" {
			return "", "", "", fmt.Errorf(i18n.T("invalid SSH target address: %s"), target)
		}
		target, port = host, parsedPort
	}
	if target == "" {
		return "", "", "", errors.New(i18n.T("SSH host must not be empty"))
	}
	return target, userName, port, nil
}

func splitCommaList(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func expandSSHPath(path, host, remoteUser, originalHost string) (string, error) {
	path = strings.Trim(path, `"`)
	home, err := os.UserHomeDir()
	if err != nil && (strings.HasPrefix(path, "~/") || strings.Contains(path, "%d")) {
		return "", fmt.Errorf(i18n.T("failed to determine the home directory: %w"), err)
	}
	path = expandSSHValue(path, host, remoteUser, originalHost)
	if strings.HasPrefix(path, "~/") {
		path = filepath.Join(home, path[2:])
	}
	return path, nil
}

func expandSSHValue(value, host, remoteUser, originalHost string) string {
	home, _ := os.UserHomeDir()
	localUser := ""
	if current, userErr := user.Current(); userErr == nil {
		localUser = current.Username
	}
	return strings.NewReplacer(
		"%d", home,
		"%h", host,
		"%n", originalHost,
		"%r", remoteUser,
		"%u", localUser,
		"%%", "%",
	).Replace(value)
}

func timeSeconds(seconds int) time.Duration {
	return time.Duration(seconds) * time.Second
}

// SSHConfigAliases returns literal host aliases suitable for shell completion.
func SSHConfigAliases(path string) ([]string, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(home, ".ssh", "config")
	} else {
		var err error
		path, err = expandSSHPath(path, "", "", "")
		if err != nil {
			return nil, err
		}
	}
	input, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer input.Close()
	parsed, err := sshconfig.Decode(input)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	var aliases []string
	for _, host := range parsed.Hosts {
		for _, pattern := range host.Patterns {
			alias := pattern.String()
			if alias == "" || strings.HasPrefix(alias, "!") || strings.ContainsAny(alias, "*?") {
				continue
			}
			if _, ok := seen[alias]; ok {
				continue
			}
			seen[alias] = struct{}{}
			aliases = append(aliases, alias)
		}
	}
	return aliases, nil
}
