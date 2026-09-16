package config

import (
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type File struct {
	Version  int    `yaml:"version"`
	Language string `yaml:"language"`
	SSH      struct {
		Target            string   `yaml:"target"`
		Port              string   `yaml:"port"`
		Password          string   `yaml:"password"`
		IdentityFile      string   `yaml:"identity_file"`
		KnownHosts        string   `yaml:"known_hosts"`
		InsecureHostKey   bool     `yaml:"insecure_host_key"`
		InteractiveAuth   *bool    `yaml:"interactive_auth"`
		JumpHosts         []string `yaml:"jump_hosts"`
		Timeout           string   `yaml:"timeout"`
		AutoReconnect     *bool    `yaml:"auto_reconnect"`
		ReconnectInterval string   `yaml:"reconnect_interval"`
		KeepAliveInterval string   `yaml:"keepalive_interval"`
	} `yaml:"ssh"`
	Proxy struct {
		HTTP         string `yaml:"http"`
		SOCKS5       string `yaml:"socks5"`
		HTTPUpstream string `yaml:"http_upstream"`
		System       *bool  `yaml:"system"`
	} `yaml:"proxy"`
	TUN struct {
		Enabled bool     `yaml:"enabled"`
		Global  bool     `yaml:"global"`
		CIDR    string   `yaml:"cidr"`
		Routes  []string `yaml:"routes"`
		NAT     []string `yaml:"nat"`
	} `yaml:"tun"`
	Routing struct {
		RulesFile string `yaml:"rules_file"`
	} `yaml:"routing"`
	Logging struct {
		Verbose bool   `yaml:"verbose"`
		File    string `yaml:"file"`
	} `yaml:"logging"`
	Service struct {
		Manager string `yaml:"manager"`
		Name    string `yaml:"name"`
		User    string `yaml:"user"`
		Group   string `yaml:"group"`
		Enable  *bool  `yaml:"enable"`
		Start   *bool  `yaml:"start"`
	} `yaml:"service"`
}

func LoadFile(path string) (*Config, string, []string, error) {
	input, err := os.Open(path)
	if err != nil {
		return nil, "", nil, fmt.Errorf("open configuration: %w", err)
	}
	defer input.Close()
	var file File
	decoder := yaml.NewDecoder(input)
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil {
		return nil, "", nil, fmt.Errorf("decode configuration: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return nil, "", nil, fmt.Errorf("decode configuration: multiple YAML documents are not allowed")
	} else if err != io.EOF {
		return nil, "", nil, fmt.Errorf("decode configuration: %w", err)
	}
	if file.Version != 0 && file.Version != 1 {
		return nil, "", nil, fmt.Errorf("unsupported configuration version %d", file.Version)
	}
	cfg := NewConfig()
	cfg.SSHServer = file.SSH.Target
	if file.SSH.Port != "" {
		cfg.SSHPort = file.SSH.Port
	}
	cfg.SSHPassword, cfg.SSHKeyFile, cfg.KnownHostsFile = file.SSH.Password, file.SSH.IdentityFile, file.SSH.KnownHosts
	cfg.InsecureHostKey, cfg.JumpHosts = file.SSH.InsecureHostKey, file.SSH.JumpHosts
	if file.SSH.InteractiveAuth != nil {
		cfg.InteractiveAuth = *file.SSH.InteractiveAuth
	}
	if file.SSH.Timeout != "" {
		cfg.Timeout, err = time.ParseDuration(file.SSH.Timeout)
		if err != nil {
			return nil, "", nil, fmt.Errorf("invalid ssh.timeout: %w", err)
		}
	}
	if file.SSH.AutoReconnect != nil {
		cfg.AutoReconnect = *file.SSH.AutoReconnect
	}
	if file.SSH.ReconnectInterval != "" {
		cfg.ReconnectInterval, err = time.ParseDuration(file.SSH.ReconnectInterval)
		if err != nil {
			return nil, "", nil, fmt.Errorf("invalid ssh.reconnect_interval: %w", err)
		}
	}
	if file.SSH.KeepAliveInterval != "" {
		cfg.KeepAliveInterval, err = time.ParseDuration(file.SSH.KeepAliveInterval)
		if err != nil {
			return nil, "", nil, fmt.Errorf("invalid ssh.keepalive_interval: %w", err)
		}
	}
	if file.Proxy.HTTP != "" {
		cfg.ListenAddr = file.Proxy.HTTP
	}
	cfg.SocksAddr, cfg.HTTPUpstream = file.Proxy.SOCKS5, file.Proxy.HTTPUpstream
	if file.Proxy.System != nil {
		cfg.SystemProxy = *file.Proxy.System
	}
	cfg.TunMode, cfg.TunGlobal = file.TUN.Enabled, file.TUN.Global
	if file.TUN.CIDR != "" {
		cfg.TunCIDR = file.TUN.CIDR
	}
	cfg.TunRoute, cfg.RuleFile = file.TUN.Routes, file.Routing.RulesFile
	cfg.Verbose, cfg.LogFile = file.Logging.Verbose, file.Logging.File
	if file.Service.Manager != "" {
		cfg.ServiceManager = file.Service.Manager
	}
	if file.Service.Name != "" {
		cfg.ServiceName = file.Service.Name
	}
	if file.Service.User != "" {
		cfg.ServiceUser = file.Service.User
	}
	if file.Service.Group != "" {
		cfg.ServiceGroup = file.Service.Group
	}
	if file.Service.Enable != nil {
		cfg.ServiceEnable = *file.Service.Enable
	}
	if file.Service.Start != nil {
		cfg.ServiceStart = *file.Service.Start
	}
	return cfg, file.Language, file.TUN.NAT, nil
}

// Template returns a complete configuration template for the current OS.
func Template(goos string) string {
	identity, knownHosts, logFile, user, group := "~/.ssh/id_ed25519", "~/.ssh/known_hosts", "", "root", "root"
	if goos == "windows" {
		identity, knownHosts, logFile, user, group = `${USERPROFILE}\.ssh\id_ed25519`, `${USERPROFILE}\.ssh\known_hosts`, `${PROGRAMDATA}\ssh-tun\ssh-tun.log`, "SYSTEM", "SYSTEM"
	}
	return fmt.Sprintf(template, identity, knownHosts, logFile, user, group)
}

const template = `version: 1
language: en

ssh:
  target: user@example.com
  port: "22"
  password: ""
  identity_file: '%s'
  known_hosts: '%s'
  insecure_host_key: false
  interactive_auth: true
  jump_hosts: []
  timeout: 10s
  auto_reconnect: false
  reconnect_interval: 5s
  keepalive_interval: 15s

proxy:
  http: ":8080"
  socks5: ""
  http_upstream: ""
  system: false

tun:
  enabled: false
  global: false
  cidr: "10.0.0.1/24"
  routes: []
  nat: []

routing:
  rules_file: ""

logging:
  verbose: false
  file: '%s'

service:
  manager: auto
  name: ssh-tun
  user: %s
  group: %s
  enable: true
  start: true
`
