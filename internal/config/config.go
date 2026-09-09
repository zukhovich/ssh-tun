package config

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/zukhovich/ssh-tun/internal/i18n"
)

// SubnetAlias defines a subnet mapping rule.
type SubnetAlias struct {
	Src *net.IPNet
	Dst *net.IPNet
}

// Config stores the resolved application configuration.
type Config struct {
	ListenAddr      string
	SSHServer       string
	SSHUser         string
	SSHPassword     string
	SSHKeyFile      string
	KnownHostsFile  string
	InsecureHostKey bool
	HTTPUpstream    string
	SSHPort         string
	SocksAddr       string
	TunMode         bool
	TunCIDR         string
	TunRoute        []string
	TunGlobal       bool
	SubnetAliases   []SubnetAlias
	JumpHosts       []string
	Timeout         time.Duration
	Verbose         bool
	LogFile         string
	InteractiveAuth bool
	SystemProxy     bool
	RuleFile        string
	ServiceManager  string
	ServiceName     string
	ServiceUser     string
	ServiceGroup    string
	ServiceEnable   bool
	ServiceStart    bool
}

// NewConfig returns the default configuration.
func NewConfig() *Config {
	return &Config{
		ListenAddr:      ":8080",
		SSHServer:       "",
		SSHPort:         "22",
		JumpHosts:       []string{},
		Timeout:         10 * time.Second,
		Verbose:         false,
		InteractiveAuth: true,
		SystemProxy:     true,
		RuleFile:        "",
		SocksAddr:       "",
		TunMode:         false,
		TunCIDR:         "10.0.0.1/24",
		TunRoute:        []string{},
		TunGlobal:       false,
		SubnetAliases:   []SubnetAlias{},
		ServiceManager:  "auto",
		ServiceName:     "ssh-tun",
		ServiceUser:     "root",
		ServiceGroup:    "root",
		ServiceEnable:   true,
		ServiceStart:    true,
	}
}

// parseJumpHost parses an SSH jump host address.
func parseJumpHost(jumpHost string) (user, host, port string, err error) {
	parts := strings.Split(jumpHost, "@")

	var hostPart string
	if len(parts) == 2 {
		user = parts[0]
		hostPart = parts[1]
	} else if len(parts) == 1 {
		hostPart = parts[0]
	} else {
		return "", "", "", fmt.Errorf(i18n.Text("invalid SSH jump-host format: %s", "неверный формат промежуточного SSH-узла: %s"), jumpHost)
	}

	if strings.HasPrefix(hostPart, "[") {
		if strings.Contains(hostPart, "]:") {
			host, port, err = net.SplitHostPort(hostPart)
		} else if strings.HasSuffix(hostPart, "]") {
			host = strings.TrimSuffix(strings.TrimPrefix(hostPart, "["), "]")
			port = "22"
		} else {
			err = fmt.Errorf(i18n.Text("invalid IPv6 address: %s", "неверный IPv6-адрес: %s"), hostPart)
		}
	} else if strings.Count(hostPart, ":") == 1 {
		host, port, err = net.SplitHostPort(hostPart)
	} else if strings.Contains(hostPart, ":") {
		return "", "", "", fmt.Errorf(i18n.Text("IPv6 addresses must be enclosed in brackets: %s", "IPv6-адрес должен быть заключён в квадратные скобки: %s"), hostPart)
	} else {
		host = hostPart
		port = "22"
	}
	if err != nil {
		return "", "", "", fmt.Errorf(i18n.Text("invalid host:port value %s: %w", "неверный формат хост:порт %s: %w"), hostPart, err)
	}

	if host == "" || port == "" {
		return "", "", "", errors.New(i18n.Text("host and port must not be empty", "имя хоста и порт не могут быть пустыми"))
	}
	if err := validatePort(port); err != nil {
		return "", "", "", err
	}

	return user, host, port, nil
}

// Validate checks the resolved configuration.
func (c *Config) Validate() error {
	if c.SSHServer == "" {
		return errors.New(i18n.Text("SSH server address is required", "необходимо указать адрес SSH-сервера"))
	}

	if c.SSHUser == "" {
		return errors.New(i18n.Text("SSH user name is required", "необходимо указать имя пользователя SSH"))
	}
	if c.Timeout <= 0 {
		return errors.New(i18n.Text("timeout must be greater than zero", "таймаут должен быть больше нуля"))
	}
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		return fmt.Errorf(i18n.Text("invalid HTTP proxy address: %w", "неверный адрес HTTP-прокси: %w"), err)
	}
	if c.SocksAddr != "" {
		if _, _, err := net.SplitHostPort(c.SocksAddr); err != nil {
			return fmt.Errorf(i18n.Text("invalid SOCKS5 proxy address: %w", "неверный адрес SOCKS5-прокси: %w"), err)
		}
	}
	if c.HTTPUpstream != "" {
		if _, _, err := net.SplitHostPort(c.HTTPUpstream); err != nil {
			return fmt.Errorf(i18n.Text("invalid upstream HTTP server address: %w", "неверный адрес вышестоящего HTTP-сервера: %w"), err)
		}
	}

	if !c.InteractiveAuth && c.SSHPassword == "" && c.SSHKeyFile == "" {
		return errors.New(i18n.Text("an SSH password, private key file, or interactive authentication is required", "необходимо указать пароль SSH, файл закрытого ключа или использовать интерактивную аутентификацию"))
	}

	for _, jumpHost := range c.JumpHosts {
		if jumpHost == "" {
			continue
		}
		_, _, _, err := parseJumpHost(jumpHost)
		if err != nil {
			return fmt.Errorf(i18n.Text("invalid SSH jump host: %w", "неверно указан промежуточный SSH-узел: %w"), err)
		}
	}

	return nil
}

func validatePort(port string) error {
	n, err := net.LookupPort("tcp", port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf(i18n.Text("invalid TCP port: %s", "неверный TCP-порт: %s"), port)
	}
	return nil
}

// ParseSubnetAlias parses a mapping between two IPv4 subnets.
func ParseSubnetAlias(value string) (SubnetAlias, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return SubnetAlias{}, fmt.Errorf(i18n.Text("invalid NAT rule %q; expected Src:Dst", "неверный формат NAT-правила %q, ожидается Src:Dst"), value)
	}
	parseNet := func(value string) (*net.IPNet, error) {
		if ip := net.ParseIP(value); ip != nil {
			ip = ip.To4()
			if ip == nil {
				return nil, fmt.Errorf(i18n.Text("IPv6 is not supported: %s", "IPv6 не поддерживается: %s"), value)
			}
			return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
		}
		ip, network, err := net.ParseCIDR(value)
		if err != nil || ip.To4() == nil {
			return nil, fmt.Errorf(i18n.Text("invalid IPv4 address or CIDR: %s", "неверный IPv4-адрес или CIDR: %s"), value)
		}
		return network, nil
	}
	src, err := parseNet(parts[0])
	if err != nil {
		return SubnetAlias{}, err
	}
	dst, err := parseNet(parts[1])
	if err != nil {
		return SubnetAlias{}, err
	}
	srcPrefix, _ := src.Mask.Size()
	dstPrefix, _ := dst.Mask.Size()
	if srcPrefix != dstPrefix {
		return SubnetAlias{}, fmt.Errorf(i18n.Text("source and destination prefix lengths differ: %d and %d", "длины масок исходной и целевой подсетей не совпадают: %d и %d"), srcPrefix, dstPrefix)
	}
	return SubnetAlias{Src: src, Dst: dst}, nil
}

// GetJumpHostInfo returns the parsed SSH jump host fields.
func (c *Config) GetJumpHostInfo(jumpHost string) (user, host, port string, err error) {
	return parseJumpHost(jumpHost)
}
