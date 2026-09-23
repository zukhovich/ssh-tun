package cli

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/zukhovich/ssh-tun/internal/config"
	"github.com/zukhovich/ssh-tun/internal/i18n"
	"github.com/zukhovich/ssh-tun/internal/logger"
	"github.com/zukhovich/ssh-tun/internal/proxy"
	"github.com/zukhovich/ssh-tun/internal/router"
	"github.com/zukhovich/ssh-tun/internal/service"
	"github.com/zukhovich/ssh-tun/internal/sysproxy"
	"github.com/zukhovich/ssh-tun/internal/tun"
)

var (
	Version        = "1.0.5"
	cfg            = config.NewConfig()
	aliasFlags     []string
	configPath     string
	writeConfig    string
	installService string
	removeService  string
	serviceName    string
	serviceUser    string
	serviceGroup   string
	serviceForce   bool
)

// rootCmd is the main application command.
var rootCmd = &cobra.Command{
	Use:     "ssh-tun [[user@]host|alias]",
	Version: Version,
	Short:   i18n.T("Lightweight SSH-based HTTP proxy"),
	Long:    i18n.T("ssh-tun is a command-line HTTP, SOCKS5, and TUN proxy over SSH.\nIt provides secure access to private networks or uses a remote host as an Internet gateway."),
	Args:    cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if writeConfig != "" {
			template := config.Template(runtime.GOOS)
			if writeConfig == "-" {
				fmt.Print(template)
				return nil
			}
			if err := os.MkdirAll(filepath.Dir(writeConfig), 0700); err != nil {
				return fmt.Errorf(i18n.T("create configuration directory: %w"), err)
			}
			if err := os.WriteFile(writeConfig, []byte(template), 0600); err != nil {
				return fmt.Errorf(i18n.T("write configuration template: %w"), err)
			}
			return nil
		}
		if installService != "" || removeService != "" {
			if configPath == "" {
				return errors.New(i18n.T("--config is required for service management"))
			}
			serviceConfig, _, err := config.LoadFile(configPath)
			if err != nil {
				return err
			}
			manager := installService
			if manager == "" {
				manager = removeService
			}
			if manager == "auto" && serviceConfig.ServiceManager != "" {
				manager = serviceConfig.ServiceManager
			}
			binary, err := os.Executable()
			if err != nil {
				return err
			}
			if !cmd.Flags().Changed("service-name") {
				serviceName = serviceConfig.ServiceName
			}
			if !cmd.Flags().Changed("service-user") {
				serviceUser = serviceConfig.ServiceUser
			}
			if !cmd.Flags().Changed("service-group") {
				serviceGroup = serviceConfig.ServiceGroup
			}
			options := service.Options{Manager: manager, Name: serviceName, Description: "ssh-tun SSH proxy", Binary: binary, Config: configPath, User: serviceUser, Group: serviceGroup, Enable: serviceConfig.ServiceEnable, Start: serviceConfig.ServiceStart, Force: serviceForce}
			if installService != "" {
				manager, err = service.Install(options)
				if err == nil {
					fmt.Printf(i18n.T("%s service %q installed\n"), manager, serviceName)
				}
			} else {
				manager, err = service.Remove(options)
				if err == nil {
					fmt.Printf(i18n.T("%s service %q removed\n"), manager, serviceName)
				}
			}
			return err
		}

		cliConfig := *cfg
		cliAliases := append([]string(nil), aliasFlags...)
		if configPath != "" {
			fileConfig, fileAliases, err := config.LoadFile(configPath)
			if err != nil {
				return err
			}
			cfg = fileConfig
			aliasFlags = fileAliases
			applyCLIOverrides(cmd, cfg, &cliConfig, &aliasFlags, cliAliases)
		}
		if len(args) == 0 && cfg.SSHServer == "" {
			return errors.New(i18n.T("SSH target is required ([user@]host or an SSH config alias)"))
		}
		// Enable TUN automatically when global routing, routes, or NAT is configured.
		if cfg.TunGlobal || len(cfg.TunRoute) > 0 || len(aliasFlags) > 0 {
			cfg.TunMode = true
		}

		if needsElevation(cfg.TunMode) {
			return elevationError()
		}

		// Resolve aliases and connection defaults from the OpenSSH client
		// configuration. Explicit ssh-tun flags override the resolved values.
		target := cfg.SSHServer
		if len(args) > 0 {
			target = args[0]
		}
		requested := *cfg
		resolved := config.NewConfig()
		resolved.SSHConfigFile = requested.SSHConfigFile
		if err := config.ResolveSSHConfig(resolved, target); err != nil {
			return err
		}
		mergeResolvedSSHConfig(cfg, &requested, resolved)

		// Add the default port when needed.
		if cfg.SSHServer != "" {
			server, err := addressWithDefaultPort(cfg.SSHServer, cfg.SSHPort)
			if err != nil {
				return err
			}
			cfg.SSHServer = server
		}

		// Parse NAT rules into runtime values.
		for _, alias := range aliasFlags {
			rule, err := config.ParseSubnetAlias(alias)
			if err != nil {
				return err
			}
			cfg.SubnetAliases = append(cfg.SubnetAliases, rule)
		}

		// Validate the resolved configuration.
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf(i18n.T("configuration error: %w"), err)
		}

		log := logger.NewLogger(cfg.Verbose)
		defer log.Close()
		if cfg.LogFile != "" {
			if err := log.SetLogFile(cfg.LogFile); err != nil {
				return fmt.Errorf(i18n.T("failed to configure the log file: %w"), err)
			}
			log.Infof(i18n.T("Logs will also be written to: %s"), cfg.LogFile)
		}
		log.Infof(i18n.T("ssh-tun %s is starting..."), Version)

		// Initialize routing rules.
		var r *router.Router
		if cfg.RuleFile != "" {
			var err error
			r, err = router.NewRouter(cfg.RuleFile)
			if err != nil {
				return fmt.Errorf(i18n.T("failed to load the routing rules file: %w"), err)
			}
			log.Infof(i18n.T("Loaded routing rules file: %s"), cfg.RuleFile)
		}

		// Initialize the SSH connection with optional auto-reconnect.
		supervisor, err := proxy.NewSupervisor(cfg, log)
		if err != nil {
			return fmt.Errorf(i18n.T("SSH connection error: %w"), err)
		}
		defer supervisor.Close()
		sshClient := supervisor.SSH()

		// Initialize the HTTP proxy.
		httpProxy, err := proxy.NewHTTPOverSSH(cfg, log, sshClient, r)
		if err != nil {
			return fmt.Errorf(i18n.T("failed to initialize the HTTP proxy: %w"), err)
		}

		// Initialize the SOCKS5 proxy.
		var socksProxy *proxy.SOCKS5OverSSH
		if cfg.SocksAddr != "" {
			socksProxy, err = proxy.NewSOCKS5OverSSH(cfg, log, sshClient, r)
			if err != nil {
				return fmt.Errorf(i18n.T("failed to initialize the SOCKS5 proxy: %w"), err)
			}
		}

		var proxyMgr *sysproxy.Manager
		if cfg.SystemProxy {
			proxyMgr = sysproxy.NewManager(log, cfg.ListenAddr, cfg.SocksAddr)
		}

		// Initialize TUN mode.
		var tunService *tun.TunService
		if cfg.TunMode {
			tunService, err = tun.NewTunService(cfg, log, sshClient, r)
			if err != nil {
				return fmt.Errorf(i18n.T("failed to initialize the TUN service: %w"), err)
			}
		}

		// Configure TUN first so startup failures cannot leave the system proxy enabled.
		if tunService != nil {
			if err := tunService.Start(); err != nil {
				return fmt.Errorf(i18n.T("failed to start the TUN service: %w"), err)
			}
			defer tunService.Close()
		}

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			if err := httpProxy.Start(); err != nil && !errors.Is(err, net.ErrClosed) {
				select {
				case sigChan <- syscall.SIGTERM:
				default:
				}
			}
		}()
		if err := httpProxy.Ready(); err != nil {
			return err
		}

		if socksProxy != nil {
			go func() {
				if err := socksProxy.Start(); err != nil && !errors.Is(err, net.ErrClosed) {
					select {
					case sigChan <- syscall.SIGTERM:
					default:
					}
				}
			}()
			if err := socksProxy.Ready(); err != nil {
				_ = httpProxy.Close()
				return err
			}
		}

		// Desktop integration is optional. A missing or unsupported gsettings
		// environment must never stop the already running SSH proxies.
		systemProxyEnabled := false
		if cfg.SystemProxy && proxyMgr != nil {
			if err := proxyMgr.Enable(); err != nil {
				log.Warnf(i18n.T("System proxy integration is unavailable; continuing without it: %v"), err)
			} else {
				systemProxyEnabled = true
				defer proxyMgr.Disable()
			}
		}

		fmt.Println("\n" + i18n.T("Proxy service started") + ":")
		fmt.Println(i18n.T("HTTP proxy:"), "http://"+cfg.ListenAddr)
		if cfg.SocksAddr != "" {
			fmt.Println(i18n.T("SOCKS5 proxy:"), "socks5://"+cfg.SocksAddr)
		}
		if cfg.TunMode {
			fmt.Printf(i18n.T("TUN mode enabled (CIDR: %s)\n"), cfg.TunCIDR)
		}

		if len(cfg.JumpHosts) > 0 {
			fmt.Printf(i18n.T("SSH jump-host chain: %v -> %s\n"), cfg.JumpHosts, cfg.SSHServer)
		} else {
			fmt.Println(i18n.T("Direct connection to SSH server:"), cfg.SSHServer)
		}
		if systemProxyEnabled {
			fmt.Println(i18n.T("System proxy enabled"))
		}
		if cfg.RuleFile != "" {
			fmt.Println(i18n.T("Custom routing rules enabled:"), cfg.RuleFile)
		}
		if cfg.AutoReconnect {
			fmt.Println(i18n.T("Auto-reconnect enabled"))
		}
		fmt.Println(i18n.T("Press Ctrl+C to exit"))

		<-sigChan
		log.Info(i18n.T("Shutdown signal received; closing proxy services..."))

		if systemProxyEnabled && proxyMgr != nil {
			if err := proxyMgr.Disable(); err != nil {
				log.Errorf(i18n.T("Failed to restore system proxy settings: %v"), err)
			}
		}

		if err := httpProxy.Close(); err != nil {
			log.Errorf(i18n.T("Failed to close the HTTP proxy: %v"), err)
		}

		if socksProxy != nil {
			if err := socksProxy.Close(); err != nil {
				log.Errorf(i18n.T("Failed to close the SOCKS5 proxy: %v"), err)
			}
		}

		if tunService != nil {
			if err := tunService.Close(); err != nil {
				log.Errorf(i18n.T("Failed to close the TUN service: %v"), err)
			}
		}

		return nil
	},
}

// init defines command-line flags.
func init() {
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", i18n.T("Path to the YAML configuration file"))
	rootCmd.PersistentFlags().StringVar(&writeConfig, "write-config", "", i18n.T("Write a configuration template to a file, or - for stdout"))
	rootCmd.PersistentFlags().StringVar(&installService, "install-service", "", i18n.T("Install a service using auto, systemd, or openrc"))
	rootCmd.PersistentFlags().StringVar(&removeService, "remove-service", "", i18n.T("Remove a service using auto, systemd, or openrc"))
	rootCmd.PersistentFlags().StringVar(&serviceName, "service-name", "ssh-tun", i18n.T("Service name"))
	rootCmd.PersistentFlags().StringVar(&serviceUser, "service-user", "root", i18n.T("Service user"))
	rootCmd.PersistentFlags().StringVar(&serviceGroup, "service-group", "root", i18n.T("Service group"))
	rootCmd.PersistentFlags().BoolVar(&serviceForce, "service-force", false, i18n.T("Overwrite an existing service definition"))
	// SSH options.
	rootCmd.PersistentFlags().StringVarP(&cfg.SSHPort, "port", "p", "22", i18n.T("SSH server port"))
	rootCmd.PersistentFlags().StringVar(&cfg.SSHPassword, "pass", "", i18n.T("SSH password (unsafe; interactive authentication is recommended)"))
	rootCmd.PersistentFlags().StringVarP(&cfg.SSHKeyFile, "identity-file", "i", "", i18n.T("Private key file"))
	rootCmd.PersistentFlags().StringVarP(&cfg.SSHConfigFile, "ssh-config", "F", "", i18n.T("OpenSSH client configuration file (default: ~/.ssh/config)"))
	rootCmd.PersistentFlags().StringVar(&cfg.SSHKeyFile, "identity_file", "", i18n.T("Deprecated: use --identity-file"))
	_ = rootCmd.PersistentFlags().MarkHidden("identity_file")
	rootCmd.PersistentFlags().StringVar(&cfg.KnownHostsFile, "known-hosts", "", i18n.T("known_hosts file (default: ~/.ssh/known_hosts)"))
	rootCmd.PersistentFlags().BoolVar(&cfg.InsecureHostKey, "insecure-host-key", false, i18n.T("Disable SSH host key verification (unsafe)"))
	rootCmd.PersistentFlags().StringSliceVarP(&cfg.JumpHosts, "jump", "J", []string{}, i18n.T("Comma-separated SSH jump hosts (user@host:port)"))
	rootCmd.PersistentFlags().DurationVar(&cfg.Timeout, "timeout", 10*time.Second, i18n.T("Connection timeout"))
	rootCmd.PersistentFlags().BoolVar(&cfg.AutoReconnect, "auto-reconnect", false, i18n.T("Reconnect automatically when the SSH channel is lost"))
	rootCmd.PersistentFlags().DurationVar(&cfg.ReconnectInterval, "reconnect-interval", 5*time.Second, i18n.T("Delay between SSH reconnect attempts"))
	rootCmd.PersistentFlags().DurationVar(&cfg.KeepAliveInterval, "keepalive-interval", 15*time.Second, i18n.T("SSH channel health-check interval"))
	rootCmd.PersistentFlags().StringVar(&cfg.HealthCheckTarget, "health-check-target", "", i18n.T("Remote TCP resource checked through SSH (for example google.com:443)"))
	rootCmd.PersistentFlags().DurationVar(&cfg.HealthCheckTimeout, "health-check-timeout", 5*time.Second, i18n.T("Remote resource health-check timeout"))

	// Proxy options.
	rootCmd.PersistentFlags().StringVarP(&cfg.ListenAddr, "listen", "l", ":8080", i18n.T("Local HTTP proxy address (deprecated; use --http)"))
	rootCmd.PersistentFlags().StringVar(&cfg.ListenAddr, "http", ":8080", i18n.T("Local HTTP proxy address"))
	rootCmd.PersistentFlags().StringVar(&cfg.SocksAddr, "socks5", "", i18n.T("SOCKS5 proxy address (for example :1080)"))
	rootCmd.PersistentFlags().BoolVar(&cfg.SystemProxy, "sys-proxy", false, i18n.T("Configure and restore the GNOME system proxy"))
	rootCmd.PersistentFlags().StringVar(&cfg.HTTPUpstream, "http-upstream", "", i18n.T("Force HTTP requests through an upstream host:port"))
	// Keep the legacy target option hidden for compatibility.
	rootCmd.PersistentFlags().StringVar(&cfg.HTTPUpstream, "target", "", i18n.T("Deprecated: use --http-upstream"))
	rootCmd.PersistentFlags().MarkHidden("target")

	// TUN options.
	rootCmd.PersistentFlags().BoolVar(&cfg.TunMode, "tun", false, i18n.T("Enable TUN mode"))
	rootCmd.PersistentFlags().BoolVarP(&cfg.TunGlobal, "tun-global", "g", false, i18n.T("Route all traffic through TUN"))
	rootCmd.PersistentFlags().StringVar(&cfg.TunCIDR, "tun-ip", "10.0.0.1/24", i18n.T("TUN device CIDR"))
	rootCmd.PersistentFlags().StringSliceVar(&cfg.TunRoute, "tun-route", []string{}, i18n.T("Add a static TUN route (repeatable)"))
	rootCmd.PersistentFlags().StringSliceVar(&aliasFlags, "tun-nat", []string{}, i18n.T("NAT mapping in SrcCIDR:DstCIDR format"))

	// General options.
	rootCmd.PersistentFlags().BoolVarP(&cfg.Verbose, "verbose", "v", false, i18n.T("Enable verbose logging"))
	rootCmd.PersistentFlags().StringVar(&cfg.LogFile, "log", "", i18n.T("Log file path"))
	rootCmd.PersistentFlags().StringVar(&cfg.RuleFile, "rules", "", i18n.T("Routing rules file"))
	rootCmd.AddCommand(newCompletionCommand())
	registerCompletions()
}

func applyCLIOverrides(cmd *cobra.Command, dst, src *config.Config, aliases *[]string, cliAliases []string) {
	copyIf := func(name string, apply func()) {
		if cmd.Flags().Changed(name) {
			apply()
		}
	}
	copyIf("port", func() { dst.SSHPort = src.SSHPort })
	copyIf("pass", func() { dst.SSHPassword = src.SSHPassword })
	copyIf("identity-file", func() { dst.SSHKeyFile = src.SSHKeyFile })
	copyIf("ssh-config", func() { dst.SSHConfigFile = src.SSHConfigFile })
	copyIf("identity_file", func() { dst.SSHKeyFile = src.SSHKeyFile })
	copyIf("known-hosts", func() { dst.KnownHostsFile = src.KnownHostsFile })
	copyIf("insecure-host-key", func() { dst.InsecureHostKey = src.InsecureHostKey })
	copyIf("jump", func() { dst.JumpHosts = src.JumpHosts })
	copyIf("timeout", func() { dst.Timeout = src.Timeout })
	copyIf("auto-reconnect", func() { dst.AutoReconnect = src.AutoReconnect })
	copyIf("reconnect-interval", func() { dst.ReconnectInterval = src.ReconnectInterval })
	copyIf("keepalive-interval", func() { dst.KeepAliveInterval = src.KeepAliveInterval })
	copyIf("health-check-target", func() { dst.HealthCheckTarget = src.HealthCheckTarget })
	copyIf("health-check-timeout", func() { dst.HealthCheckTimeout = src.HealthCheckTimeout })
	copyIf("http", func() { dst.ListenAddr = src.ListenAddr })
	copyIf("listen", func() { dst.ListenAddr = src.ListenAddr })
	copyIf("socks5", func() { dst.SocksAddr = src.SocksAddr })
	copyIf("sys-proxy", func() { dst.SystemProxy = src.SystemProxy })
	copyIf("http-upstream", func() { dst.HTTPUpstream = src.HTTPUpstream })
	copyIf("tun", func() { dst.TunMode = src.TunMode })
	copyIf("tun-global", func() { dst.TunGlobal = src.TunGlobal })
	copyIf("tun-ip", func() { dst.TunCIDR = src.TunCIDR })
	copyIf("tun-route", func() { dst.TunRoute = src.TunRoute })
	copyIf("tun-nat", func() { *aliases = cliAliases })
	copyIf("verbose", func() { dst.Verbose = src.Verbose })
	copyIf("log", func() { dst.LogFile = src.LogFile })
	copyIf("rules", func() { dst.RuleFile = src.RuleFile })
}

func Execute(version string) {
	Version = version
	rootCmd.Version = version
	i18n.Init("")
	localizeCLI()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func localizeCLI() {
	rootCmd.InitDefaultHelpFlag()
	rootCmd.InitDefaultVersionFlag()
	rootCmd.Short, rootCmd.Long = i18n.T("Lightweight SSH-based HTTP proxy"), i18n.T("ssh-tun is a command-line HTTP, SOCKS5, and TUN proxy over SSH.\nIt provides secure access to private networks or uses a remote host as an Internet gateway.")
	rootCmd.SetUsageFunc(func(cmd *cobra.Command) error {
		usage, flags := i18n.T("Usage"), i18n.T("Flags")
		fmt.Fprintf(cmd.OutOrStderr(), "%s:\n  %s\n\n%s:\n%s", usage, cmd.UseLine(), flags, cmd.LocalFlags().FlagUsages())
		return nil
	})
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, _ []string) {
		fmt.Fprintln(cmd.OutOrStdout(), cmd.Long)
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintf(cmd.OutOrStdout(), i18n.T("Usage:\n  %s\n\nFlags:\n%s"), cmd.UseLine(), cmd.LocalFlags().FlagUsages())
	})
	usages := map[string]string{
		"config":          i18n.T("Path to the YAML configuration file"),
		"write-config":    i18n.T("Write a configuration template to a file, or - for stdout"),
		"install-service": i18n.T("Install a service using auto, systemd, or openrc"), "remove-service": i18n.T("Remove a service using auto, systemd, or openrc"),
		"service-name": i18n.T("Service name"), "service-user": i18n.T("Service user"), "service-group": i18n.T("Service group"),
		"port": i18n.T("SSH server port"), "pass": i18n.T("SSH password (unsafe; interactive authentication is recommended)"),
		"identity-file": i18n.T("Private key file"), "ssh-config": i18n.T("OpenSSH client configuration file (default: ~/.ssh/config)"), "known-hosts": i18n.T("known_hosts file (default: ~/.ssh/known_hosts)"),
		"insecure-host-key": i18n.T("Disable SSH host key verification (unsafe)"), "jump": i18n.T("Comma-separated SSH jump hosts (user@host:port)"),
		"timeout": i18n.T("Connection timeout"), "listen": i18n.T("Local HTTP proxy address (deprecated; use --http)"),
		"http": i18n.T("Local HTTP proxy address"), "socks5": i18n.T("SOCKS5 proxy address (for example :1080)"),
		"sys-proxy": i18n.T("Configure and restore the GNOME system proxy"), "http-upstream": i18n.T("Force HTTP requests through an upstream host:port"),
		"tun": i18n.T("Enable TUN mode"), "tun-global": i18n.T("Route all traffic through TUN"), "tun-ip": i18n.T("TUN device CIDR"),
		"tun-route": i18n.T("Add a static TUN route (repeatable)"), "tun-nat": i18n.T("NAT mapping in SrcCIDR:DstCIDR format"),
		"verbose": i18n.T("Enable verbose logging"), "log": i18n.T("Log file path"), "rules": i18n.T("Routing rules file"),
	}

	for name, message := range usages {
		if flag := rootCmd.PersistentFlags().Lookup(name); flag != nil {
			flag.Usage = message
		}
	}
	setFlagUsage(rootCmd, "help", i18n.T("help for ssh-tun"))
	setFlagUsage(rootCmd, "version", i18n.T("version for ssh-tun"))
	if completion, _, err := rootCmd.Find([]string{"completion"}); err == nil && completion != rootCmd {
		completion.Short = i18n.T("Generate shell completion script")
	}
	if flag := rootCmd.PersistentFlags().Lookup("service-force"); flag != nil {
		flag.Usage = i18n.T("Overwrite an existing service definition")
	}
	setFlagUsage(rootCmd, "auto-reconnect", i18n.T("Reconnect automatically when the SSH channel is lost"))
	setFlagUsage(rootCmd, "reconnect-interval", i18n.T("Delay between SSH reconnect attempts"))
	setFlagUsage(rootCmd, "keepalive-interval", i18n.T("SSH channel health-check interval"))
	setFlagUsage(rootCmd, "health-check-target", i18n.T("Remote TCP resource checked through SSH (for example google.com:443)"))
	setFlagUsage(rootCmd, "health-check-timeout", i18n.T("Remote resource health-check timeout"))
}

func setFlagUsage(cmd *cobra.Command, name, usage string) {
	sets := []*pflag.FlagSet{cmd.Flags(), cmd.PersistentFlags(), cmd.InheritedFlags(), cmd.LocalNonPersistentFlags()}
	for _, flags := range sets {
		if flag := flags.Lookup(name); flag != nil {
			flag.Usage = usage
		}
	}
}

func mergeResolvedSSHConfig(dst, requested, resolved *config.Config) {
	dst.SSHServer, dst.SSHUser = resolved.SSHServer, resolved.SSHUser
	if requested.SSHPort == "" || requested.SSHPort == "22" {
		dst.SSHPort = resolved.SSHPort
	}
	if requested.SSHKeyFile == "" {
		dst.SSHKeyFiles = resolved.SSHKeyFiles
	}
	if requested.KnownHostsFile == "" {
		dst.KnownHostsFile = resolved.KnownHostsFile
	}
	if len(requested.JumpHosts) == 0 {
		dst.JumpHosts = resolved.JumpHosts
	}
	if requested.Timeout == 10*time.Second {
		dst.Timeout = resolved.Timeout
	}
}

func addressWithDefaultPort(host, port string) (string, error) {
	if err := validatePort(port); err != nil {
		return "", err
	}
	if parsedHost, parsedPort, err := net.SplitHostPort(host); err == nil {
		if parsedHost == "" {
			return "", errors.New(i18n.T("SSH server host must not be empty"))
		}
		if err := validatePort(parsedPort); err != nil {
			return "", err
		}
		return host, nil
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return net.JoinHostPort(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"), port), nil
	}
	if strings.Contains(host, ":") {
		return "", fmt.Errorf(i18n.T("invalid SSH server address: %s"), host)
	}
	return net.JoinHostPort(host, port), nil
}

func validatePort(port string) error {
	value, err := net.LookupPort("tcp", port)
	if err != nil || value < 1 || value > 65535 {
		return fmt.Errorf(i18n.T("invalid SSH port: %s"), port)
	}
	return nil
}
