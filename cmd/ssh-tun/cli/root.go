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
	Version        = "1.0.3"
	cfg            = config.NewConfig()
	aliasFlags     []string
	configPath     string
	language       string
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
	Use:     "ssh-tun [user@host]",
	Version: Version,
	Short:   i18n.T(i18n.AppShort),
	Long:    i18n.T(i18n.AppLong),
	Args:    cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := i18n.Set(language); err != nil {
			return err
		}
		if writeConfig != "" {
			template := config.Template(runtime.GOOS)
			if writeConfig == "-" {
				fmt.Print(template)
				return nil
			}
			if err := os.MkdirAll(filepath.Dir(writeConfig), 0700); err != nil {
				return fmt.Errorf("create configuration directory: %w", err)
			}
			if err := os.WriteFile(writeConfig, []byte(template), 0600); err != nil {
				return fmt.Errorf("write configuration template: %w", err)
			}
			return nil
		}
		if installService != "" || removeService != "" {
			if configPath == "" {
				return fmt.Errorf("--config is required for service management")
			}
			serviceConfig, fileLanguage, _, err := config.LoadFile(configPath)
			if err != nil {
				return err
			}
			if !cmd.Flags().Changed("lang") && fileLanguage != "" {
				language = fileLanguage
				if err := i18n.Set(language); err != nil {
					return err
				}
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
					fmt.Println(i18n.T(i18n.ServiceInstalled, manager, serviceName))
				}
			} else {
				manager, err = service.Remove(options)
				if err == nil {
					fmt.Println(i18n.T(i18n.ServiceRemoved, manager, serviceName))
				}
			}
			return err
		}

		cliConfig := *cfg
		cliAliases := append([]string(nil), aliasFlags...)
		if configPath != "" {
			fileConfig, fileLanguage, fileAliases, err := config.LoadFile(configPath)
			if err != nil {
				return err
			}
			if !cmd.Flags().Changed("lang") && fileLanguage != "" {
				language = fileLanguage
				if err := i18n.Set(language); err != nil {
					return err
				}
			}
			cfg = fileConfig
			aliasFlags = fileAliases
			applyCLIOverrides(cmd, cfg, &cliConfig, &aliasFlags, cliAliases)
		}
		if len(args) == 0 && cfg.SSHServer == "" {
			return errors.New(i18n.Text("SSH target is required (user@host)", "необходимо указать SSH-цель (user@host)"))
		}
		// Enable TUN automatically when global routing, routes, or NAT is configured.
		if cfg.TunGlobal || len(cfg.TunRoute) > 0 || len(aliasFlags) > 0 {
			cfg.TunMode = true
		}

		if needsElevation(cfg.TunMode) {
			fmt.Println(i18n.Text("TUN mode requires elevated privileges. Restarting...", "Для TUN-режима нужны повышенные привилегии. Перезапуск..."))
			if err := relaunchElevated(); err != nil {
				return err
			}
			return nil
		}

		// Resolve the SSH user and server from CLI or configuration.
		if len(args) > 0 {
			user, host, err := parseSSHTarget(args[0])
			if err != nil {
				return err
			}
			cfg.SSHUser, cfg.SSHServer = user, host
		} else {
			user, host, err := parseSSHTarget(cfg.SSHServer)
			if err != nil {
				return err
			}
			cfg.SSHUser, cfg.SSHServer = user, host
		}

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
			return fmt.Errorf(i18n.Text("configuration error: %w", "ошибка конфигурации: %w"), err)
		}

		log := logger.NewLogger(cfg.Verbose)
		defer log.Close()
		if cfg.LogFile != "" {
			if err := log.SetLogFile(cfg.LogFile); err != nil {
				return fmt.Errorf(i18n.Text("failed to configure the log file: %w", "не удалось настроить файл журнала: %w"), err)
			}
			log.Infof(i18n.Text("Logs will also be written to: %s", "Журнал также будет записываться в файл: %s"), cfg.LogFile)
		}
		log.Infof(i18n.Text("ssh-tun %s is starting...", "ssh-tun %s запускается..."), Version)

		// Initialize routing rules.
		var r *router.Router
		if cfg.RuleFile != "" {
			var err error
			r, err = router.NewRouter(cfg.RuleFile)
			if err != nil {
				return fmt.Errorf(i18n.Text("failed to load the routing rules file: %w", "не удалось загрузить файл правил маршрутизации: %w"), err)
			}
			log.Infof(i18n.Text("Loaded routing rules file: %s", "Загружен файл правил маршрутизации: %s"), cfg.RuleFile)
		}

		// Initialize the SSH connection with optional auto-reconnect.
		supervisor, err := proxy.NewSupervisor(cfg, log)
		if err != nil {
			return fmt.Errorf(i18n.Text("SSH connection error: %w", "ошибка SSH-подключения: %w"), err)
		}
		defer supervisor.Close()
		sshClient := supervisor.SSH()

		// Initialize the HTTP proxy.
		httpProxy, err := proxy.NewHTTPOverSSH(cfg, log, sshClient, r)
		if err != nil {
			return fmt.Errorf(i18n.Text("failed to initialize the HTTP proxy: %w", "ошибка инициализации HTTP-прокси: %w"), err)
		}

		// Initialize the SOCKS5 proxy.
		var socksProxy *proxy.SOCKS5OverSSH
		if cfg.SocksAddr != "" {
			socksProxy, err = proxy.NewSOCKS5OverSSH(cfg, log, sshClient, r)
			if err != nil {
				return fmt.Errorf(i18n.Text("failed to initialize the SOCKS5 proxy: %w", "ошибка инициализации SOCKS5-прокси: %w"), err)
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
				return fmt.Errorf(i18n.Text("failed to initialize the TUN service: %w", "ошибка инициализации TUN-сервиса: %w"), err)
			}
		}

		// Configure TUN first so startup failures cannot leave the system proxy enabled.
		if tunService != nil {
			if err := tunService.Start(); err != nil {
				return fmt.Errorf(i18n.Text("failed to start the TUN service: %w", "не удалось запустить TUN-сервис: %w"), err)
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
				log.Warnf(i18n.Text("System proxy integration is unavailable; continuing without it: %v", "Интеграция с системным прокси недоступна; работа продолжается без неё: %v"), err)
			} else {
				systemProxyEnabled = true
				defer proxyMgr.Disable()
			}
		}

		fmt.Println("\n" + i18n.T(i18n.Started) + ":")
		fmt.Println(i18n.Text("HTTP proxy:", "HTTP-прокси:"), "http://"+cfg.ListenAddr)
		if cfg.SocksAddr != "" {
			fmt.Println(i18n.Text("SOCKS5 proxy:", "SOCKS5-прокси:"), "socks5://"+cfg.SocksAddr)
		}
		if cfg.TunMode {
			fmt.Printf(i18n.Text("TUN mode enabled (CIDR: %s)\n", "TUN-режим включён (CIDR: %s)\n"), cfg.TunCIDR)
		}

		if len(cfg.JumpHosts) > 0 {
			fmt.Printf(i18n.Text("SSH jump-host chain: %v -> %s\n", "Цепочка промежуточных SSH-узлов: %v -> %s\n"), cfg.JumpHosts, cfg.SSHServer)
		} else {
			fmt.Println(i18n.Text("Direct connection to SSH server:", "Прямое подключение к SSH-серверу:"), cfg.SSHServer)
		}
		if systemProxyEnabled {
			fmt.Println(i18n.Text("System proxy enabled", "Системный прокси включён"))
		}
		if cfg.RuleFile != "" {
			fmt.Println(i18n.Text("Custom routing rules enabled:", "Пользовательские правила маршрутизации включены:"), cfg.RuleFile)
		}
		if cfg.AutoReconnect {
			fmt.Println(i18n.Text("Auto-reconnect enabled", "Автоматическое переподключение включено"))
		}
		fmt.Println(i18n.T(i18n.PressExit))

		<-sigChan
		log.Info(i18n.Text("Shutdown signal received; closing proxy services...", "Получен сигнал, закрытие прокси-сервисов..."))

		if systemProxyEnabled && proxyMgr != nil {
			if err := proxyMgr.Disable(); err != nil {
				log.Errorf(i18n.Text("Failed to restore system proxy settings: %v", "Не удалось восстановить настройки системного прокси: %v"), err)
			}
		}

		if err := httpProxy.Close(); err != nil {
			log.Errorf(i18n.Text("Failed to close the HTTP proxy: %v", "Не удалось закрыть HTTP-прокси: %v"), err)
		}

		if socksProxy != nil {
			if err := socksProxy.Close(); err != nil {
				log.Errorf(i18n.Text("Failed to close the SOCKS5 proxy: %v", "Не удалось закрыть SOCKS5-прокси: %v"), err)
			}
		}

		if tunService != nil {
			if err := tunService.Close(); err != nil {
				log.Errorf(i18n.Text("Failed to close the TUN service: %v", "Не удалось закрыть TUN-сервис: %v"), err)
			}
		}

		return nil
	},
}

// init defines command-line flags.
func init() {
	language = "en"
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", i18n.T(i18n.FlagConfig))
	rootCmd.PersistentFlags().StringVar(&language, "lang", language, i18n.T(i18n.FlagLanguage))
	rootCmd.PersistentFlags().StringVar(&writeConfig, "write-config", "", "Write a configuration template to a file, or - for stdout")
	rootCmd.PersistentFlags().StringVar(&installService, "install-service", "", i18n.T(i18n.FlagServiceInstall))
	rootCmd.PersistentFlags().StringVar(&removeService, "remove-service", "", i18n.T(i18n.FlagServiceRemove))
	rootCmd.PersistentFlags().StringVar(&serviceName, "service-name", "ssh-tun", i18n.T(i18n.FlagServiceName))
	rootCmd.PersistentFlags().StringVar(&serviceUser, "service-user", "root", i18n.T(i18n.FlagServiceUser))
	rootCmd.PersistentFlags().StringVar(&serviceGroup, "service-group", "root", i18n.T(i18n.FlagServiceGroup))
	rootCmd.PersistentFlags().BoolVar(&serviceForce, "service-force", false, "Overwrite an existing service definition")
	// SSH options.
	rootCmd.PersistentFlags().StringVarP(&cfg.SSHPort, "port", "p", "22", i18n.T(i18n.FlagSSHPort))
	rootCmd.PersistentFlags().StringVar(&cfg.SSHPassword, "pass", "", i18n.T(i18n.FlagPassword))
	rootCmd.PersistentFlags().StringVarP(&cfg.SSHKeyFile, "identity-file", "i", "", i18n.T(i18n.FlagIdentity))
	rootCmd.PersistentFlags().StringVar(&cfg.SSHKeyFile, "identity_file", "", "Deprecated: use --identity-file")
	_ = rootCmd.PersistentFlags().MarkHidden("identity_file")
	rootCmd.PersistentFlags().StringVar(&cfg.KnownHostsFile, "known-hosts", "", i18n.T(i18n.FlagKnownHosts))
	rootCmd.PersistentFlags().BoolVar(&cfg.InsecureHostKey, "insecure-host-key", false, i18n.T(i18n.FlagInsecure))
	rootCmd.PersistentFlags().StringSliceVarP(&cfg.JumpHosts, "jump", "J", []string{}, i18n.T(i18n.FlagJump))
	rootCmd.PersistentFlags().DurationVar(&cfg.Timeout, "timeout", 10*time.Second, i18n.T(i18n.FlagTimeout))
	rootCmd.PersistentFlags().BoolVar(&cfg.AutoReconnect, "auto-reconnect", false, "Reconnect automatically when the SSH channel is lost")
	rootCmd.PersistentFlags().DurationVar(&cfg.ReconnectInterval, "reconnect-interval", 5*time.Second, "Delay between SSH reconnect attempts")
	rootCmd.PersistentFlags().DurationVar(&cfg.KeepAliveInterval, "keepalive-interval", 15*time.Second, "SSH channel health-check interval")

	// Proxy options.
	rootCmd.PersistentFlags().StringVarP(&cfg.ListenAddr, "listen", "l", ":8080", i18n.T(i18n.FlagListen))
	rootCmd.PersistentFlags().StringVar(&cfg.ListenAddr, "http", ":8080", i18n.T(i18n.FlagHTTP))
	rootCmd.PersistentFlags().StringVar(&cfg.SocksAddr, "socks5", "", i18n.T(i18n.FlagSOCKS))
	rootCmd.PersistentFlags().BoolVar(&cfg.SystemProxy, "sys-proxy", false, i18n.T(i18n.FlagSysProxy))
	rootCmd.PersistentFlags().StringVar(&cfg.HTTPUpstream, "http-upstream", "", i18n.T(i18n.FlagUpstream))
	// Keep the legacy target option hidden for compatibility.
	rootCmd.PersistentFlags().StringVar(&cfg.HTTPUpstream, "target", "", "Deprecated: use --http-upstream")
	rootCmd.PersistentFlags().MarkHidden("target")

	// TUN options.
	rootCmd.PersistentFlags().BoolVar(&cfg.TunMode, "tun", false, i18n.T(i18n.FlagTUN))
	rootCmd.PersistentFlags().BoolVarP(&cfg.TunGlobal, "tun-global", "g", false, i18n.T(i18n.FlagTUNGlobal))
	rootCmd.PersistentFlags().StringVar(&cfg.TunCIDR, "tun-ip", "10.0.0.1/24", i18n.T(i18n.FlagTUNIP))
	rootCmd.PersistentFlags().StringSliceVar(&cfg.TunRoute, "tun-route", []string{}, i18n.T(i18n.FlagTUNRoute))
	rootCmd.PersistentFlags().StringSliceVar(&aliasFlags, "tun-nat", []string{}, i18n.T(i18n.FlagTUNNAT))

	// General options.
	rootCmd.PersistentFlags().BoolVarP(&cfg.Verbose, "verbose", "v", false, i18n.T(i18n.FlagVerbose))
	rootCmd.PersistentFlags().StringVar(&cfg.LogFile, "log", "", i18n.T(i18n.FlagLog))
	rootCmd.PersistentFlags().StringVar(&cfg.RuleFile, "rules", "", i18n.T(i18n.FlagRules))
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
	copyIf("identity_file", func() { dst.SSHKeyFile = src.SSHKeyFile })
	copyIf("known-hosts", func() { dst.KnownHostsFile = src.KnownHostsFile })
	copyIf("insecure-host-key", func() { dst.InsecureHostKey = src.InsecureHostKey })
	copyIf("jump", func() { dst.JumpHosts = src.JumpHosts })
	copyIf("timeout", func() { dst.Timeout = src.Timeout })
	copyIf("auto-reconnect", func() { dst.AutoReconnect = src.AutoReconnect })
	copyIf("reconnect-interval", func() { dst.ReconnectInterval = src.ReconnectInterval })
	copyIf("keepalive-interval", func() { dst.KeepAliveInterval = src.KeepAliveInterval })
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
	bootstrapLanguage()
	localizeCLI()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func bootstrapLanguage() {
	args := os.Args[1:]
	for index, arg := range args {
		if arg == "--lang" && index+1 < len(args) {
			language = args[index+1]
		}
		if strings.HasPrefix(arg, "--lang=") {
			language = strings.TrimPrefix(arg, "--lang=")
		}
	}
	_ = i18n.Set(language)
}

func localizeCLI() {
	rootCmd.InitDefaultHelpFlag()
	rootCmd.InitDefaultVersionFlag()
	rootCmd.Short, rootCmd.Long = i18n.T(i18n.AppShort), i18n.T(i18n.AppLong)
	rootCmd.SetUsageFunc(func(cmd *cobra.Command) error {
		language := i18n.Language()
		usage, flags := "Usage", "Flags"
		if language == "ru" {
			usage, flags = "Использование", "Флаги"
		}
		fmt.Fprintf(cmd.OutOrStderr(), "%s:\n  %s\n\n%s:\n%s", usage, cmd.UseLine(), flags, cmd.LocalFlags().FlagUsages())
		return nil
	})
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, _ []string) {
		fmt.Fprintln(cmd.OutOrStdout(), cmd.Long)
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintf(cmd.OutOrStdout(), i18n.Text("Usage:\n  %s\n\nFlags:\n%s", "Использование:\n  %s\n\nФлаги:\n%s"), cmd.UseLine(), cmd.LocalFlags().FlagUsages())
	})
	usages := map[string]i18n.ID{
		"config": i18n.FlagConfig, "lang": i18n.FlagLanguage, "install-service": i18n.FlagServiceInstall,
		"remove-service": i18n.FlagServiceRemove, "service-name": i18n.FlagServiceName, "service-user": i18n.FlagServiceUser,
		"service-group": i18n.FlagServiceGroup, "port": i18n.FlagSSHPort, "pass": i18n.FlagPassword,
		"identity-file": i18n.FlagIdentity, "known-hosts": i18n.FlagKnownHosts, "insecure-host-key": i18n.FlagInsecure,
		"jump": i18n.FlagJump, "timeout": i18n.FlagTimeout, "listen": i18n.FlagListen, "http": i18n.FlagHTTP,
		"socks5": i18n.FlagSOCKS, "sys-proxy": i18n.FlagSysProxy, "http-upstream": i18n.FlagUpstream,
		"tun": i18n.FlagTUN, "tun-global": i18n.FlagTUNGlobal, "tun-ip": i18n.FlagTUNIP,
		"tun-route": i18n.FlagTUNRoute, "tun-nat": i18n.FlagTUNNAT, "verbose": i18n.FlagVerbose,
		"log": i18n.FlagLog, "rules": i18n.FlagRules,
	}
	for name, id := range usages {
		if flag := rootCmd.PersistentFlags().Lookup(name); flag != nil {
			flag.Usage = i18n.T(id)
		}
	}
	setFlagUsage(rootCmd, "help", i18n.Text("help for ssh-tun", "показать справку по ssh-tun"))
	setFlagUsage(rootCmd, "version", i18n.Text("version for ssh-tun", "показать версию ssh-tun"))
	if flag := rootCmd.PersistentFlags().Lookup("write-config"); flag != nil {
		flag.Usage = i18n.Text("Write a configuration template to a file, or - for stdout", "Записать шаблон конфигурации в файл или вывести в stdout при значении -")
	}
	if flag := rootCmd.PersistentFlags().Lookup("service-force"); flag != nil {
		flag.Usage = i18n.Text("Overwrite an existing service definition", "Перезаписать существующее определение службы")
	}
	setFlagUsage(rootCmd, "auto-reconnect", i18n.Text("Reconnect automatically when the SSH channel is lost", "Автоматически переподключаться при обрыве SSH-канала"))
	setFlagUsage(rootCmd, "reconnect-interval", i18n.Text("Delay between SSH reconnect attempts", "Пауза между попытками переподключения SSH"))
	setFlagUsage(rootCmd, "keepalive-interval", i18n.Text("SSH channel health-check interval", "Интервал проверки состояния SSH-канала"))
}

func setFlagUsage(cmd *cobra.Command, name, usage string) {
	sets := []*pflag.FlagSet{cmd.Flags(), cmd.PersistentFlags(), cmd.InheritedFlags(), cmd.LocalNonPersistentFlags()}
	for _, flags := range sets {
		if flag := flags.Lookup(name); flag != nil {
			flag.Usage = usage
		}
	}
}

// parseSSHTarget parses an SSH target in user@host format.
func parseSSHTarget(target string) (string, string, error) {
	if target == "" {
		return "", "", nil
	}

	at := strings.LastIndex(target, "@")
	if at <= 0 || at == len(target)-1 || strings.Contains(target[:at], "@") {
		return "", "", errors.New(i18n.Text("invalid SSH target; expected user@host", "неверный формат SSH-цели, требуется формат user@host"))
	}

	user := target[:at]
	host := target[at+1:]

	// Validate parsed values.
	if user == "" || host == "" {
		return "", "", errors.New(i18n.Text("user name and host must not be empty", "имя пользователя или хост не могут быть пустыми"))
	}

	return user, host, nil
}

func addressWithDefaultPort(host, port string) (string, error) {
	if err := validatePort(port); err != nil {
		return "", err
	}
	if parsedHost, parsedPort, err := net.SplitHostPort(host); err == nil {
		if parsedHost == "" {
			return "", errors.New(i18n.Text("SSH server host must not be empty", "хост SSH-сервера не может быть пустым"))
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
		return "", fmt.Errorf(i18n.Text("invalid SSH server address: %s", "неверный адрес SSH-сервера: %s"), host)
	}
	return net.JoinHostPort(host, port), nil
}

func validatePort(port string) error {
	value, err := net.LookupPort("tcp", port)
	if err != nil || value < 1 || value > 65535 {
		return fmt.Errorf(i18n.Text("invalid SSH port: %s", "неверный порт SSH: %s"), port)
	}
	return nil
}
