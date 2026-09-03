package cli

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
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
	Version        = "1.0.0"
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
			if writeConfig == "-" {
				fmt.Print(config.Template)
				return nil
			}
			if err := os.WriteFile(writeConfig, []byte(config.Template), 0600); err != nil {
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
			return fmt.Errorf("SSH target is required (user@host)")
		}
		// Enable TUN automatically when global routing, routes, or NAT is configured.
		if cfg.TunGlobal || len(cfg.TunRoute) > 0 || len(aliasFlags) > 0 {
			cfg.TunMode = true
		}

		// Creating a TUN device and routes requires root privileges.
		if cfg.TunMode && os.Geteuid() != 0 {
			fmt.Println("Для TUN-режима нужны права root. Перезапуск через sudo...")

			exe, err := os.Executable()
			if err != nil {
				return fmt.Errorf("не удалось получить путь к исполняемому файлу: %w", err)
			}

			sudoArgs := []string{"sudo", exe}
			sudoArgs = append(sudoArgs, os.Args[1:]...)

			if err := syscall.Exec("/usr/bin/sudo", sudoArgs, os.Environ()); err != nil {
				return fmt.Errorf("не удалось перезапустить приложение через sudo: %w", err)
			}
			return nil // syscall.Exec does not return on success.
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
			return fmt.Errorf("ошибка конфигурации: %w", err)
		}

		log := logger.NewLogger(cfg.Verbose)
		defer log.Close()
		if cfg.LogFile != "" {
			if err := log.SetLogFile(cfg.LogFile); err != nil {
				return fmt.Errorf("не удалось настроить файл журнала: %w", err)
			}
			log.Infof("Журнал будет выводиться в файл: %s", cfg.LogFile)
		}
		log.Infof("ssh-tun %s запускается...", Version)

		// Initialize routing rules.
		var r *router.Router
		if cfg.RuleFile != "" {
			var err error
			r, err = router.NewRouter(cfg.RuleFile)
			if err != nil {
				return fmt.Errorf("не удалось загрузить файл правил: %w", err)
			}
			log.Infof("Загружен файл правил: %s", cfg.RuleFile)
		}

		// Initialize the SSH client.
		sshClient, err := proxy.NewSSHClient(cfg, log)
		if err != nil {
			return fmt.Errorf("ошибка SSH-подключения: %w", err)
		}
		defer sshClient.Close()

		// Initialize the HTTP proxy.
		httpProxy, err := proxy.NewHTTPOverSSH(cfg, log, sshClient, r)
		if err != nil {
			return fmt.Errorf("ошибка инициализации HTTP-прокси: %w", err)
		}

		// Initialize the SOCKS5 proxy.
		var socksProxy *proxy.SOCKS5OverSSH
		if cfg.SocksAddr != "" {
			socksProxy, err = proxy.NewSOCKS5OverSSH(cfg, log, sshClient, r)
			if err != nil {
				return fmt.Errorf("ошибка инициализации SOCKS5-прокси: %w", err)
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
				return fmt.Errorf("ошибка инициализации TUN-сервиса: %w", err)
			}
		}

		// Configure TUN first so startup failures cannot leave the system proxy enabled.
		if tunService != nil {
			if err := tunService.Start(); err != nil {
				return fmt.Errorf("не удалось запустить TUN-сервис: %w", err)
			}
			defer tunService.Close()
		}

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			if err := httpProxy.Start(); err != nil {
				log.Errorf("Не удалось запустить HTTP-прокси: %v", err)
				sigChan <- syscall.SIGTERM
			}
		}()

		if socksProxy != nil {
			go func() {
				if err := socksProxy.Start(); err != nil {
					log.Errorf("Не удалось запустить SOCKS5-прокси: %v", err)
					sigChan <- syscall.SIGTERM
				}
			}()
		}

		// Allow listeners to bind before changing desktop proxy settings.
		time.Sleep(50 * time.Millisecond)
		if cfg.SystemProxy && proxyMgr != nil {
			if err := proxyMgr.Enable(); err != nil {
				_ = httpProxy.Close()
				if socksProxy != nil {
					_ = socksProxy.Close()
				}
				return fmt.Errorf("не удалось настроить системный прокси: %w", err)
			}
			defer proxyMgr.Disable()
		}

		fmt.Println("\n" + i18n.T(i18n.Started) + ":")
		fmt.Println("HTTP-прокси:", "http://"+cfg.ListenAddr)
		if cfg.SocksAddr != "" {
			fmt.Println("SOCKS5-прокси:", "socks5://"+cfg.SocksAddr)
		}
		if cfg.TunMode {
			fmt.Printf("TUN-режим включён (CIDR: %s)\n", cfg.TunCIDR)
		}

		if len(cfg.JumpHosts) > 0 {
			fmt.Printf("Цепочка промежуточных SSH-узлов: %v -> %s\n", cfg.JumpHosts, cfg.SSHServer)
		} else {
			fmt.Println("Прямое подключение к SSH-серверу:", cfg.SSHServer)
		}
		if cfg.SystemProxy {
			fmt.Println("Системный прокси включён")
		}
		if cfg.RuleFile != "" {
			fmt.Println("Пользовательские правила маршрутизации включены:", cfg.RuleFile)
		}
		fmt.Println(i18n.T(i18n.PressExit))

		<-sigChan
		log.Info("Получен сигнал, закрытие прокси-сервисов...")

		if cfg.SystemProxy && proxyMgr != nil {
			if err := proxyMgr.Disable(); err != nil {
				log.Errorf("Не удалось восстановить настройки системного прокси: %v", err)
			}
		}

		if err := httpProxy.Close(); err != nil {
			log.Errorf("Не удалось закрыть HTTP-прокси: %v", err)
		}

		if socksProxy != nil {
			if err := socksProxy.Close(); err != nil {
				log.Errorf("Не удалось закрыть SOCKS5-прокси: %v", err)
			}
		}

		if tunService != nil {
			if err := tunService.Close(); err != nil {
				log.Errorf("Не удалось закрыть TUN-сервис: %v", err)
			}
		}

		return nil
	},
}

// init defines command-line flags.
func init() {
	language = i18n.Detect()
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
	rootCmd.PersistentFlags().StringVarP(&cfg.SSHKeyFile, "identity_file", "i", "", i18n.T(i18n.FlagIdentity))
	rootCmd.PersistentFlags().StringVar(&cfg.KnownHostsFile, "known-hosts", "", i18n.T(i18n.FlagKnownHosts))
	rootCmd.PersistentFlags().BoolVar(&cfg.InsecureHostKey, "insecure-host-key", false, i18n.T(i18n.FlagInsecure))
	rootCmd.PersistentFlags().StringSliceVarP(&cfg.JumpHosts, "jump", "J", []string{}, i18n.T(i18n.FlagJump))
	rootCmd.PersistentFlags().DurationVar(&cfg.Timeout, "timeout", 10*time.Second, i18n.T(i18n.FlagTimeout))

	// Proxy options.
	rootCmd.PersistentFlags().StringVarP(&cfg.ListenAddr, "listen", "l", ":8080", i18n.T(i18n.FlagListen))
	rootCmd.PersistentFlags().StringVar(&cfg.ListenAddr, "http", ":8080", i18n.T(i18n.FlagHTTP))
	rootCmd.PersistentFlags().StringVar(&cfg.SocksAddr, "socks5", "", i18n.T(i18n.FlagSOCKS))
	rootCmd.PersistentFlags().BoolVar(&cfg.SystemProxy, "sys-proxy", true, i18n.T(i18n.FlagSysProxy))
	rootCmd.PersistentFlags().StringVar(&cfg.HTTPUpstream, "http-upstream", "", i18n.T(i18n.FlagUpstream))
	// Keep the legacy target option hidden for compatibility.
	rootCmd.PersistentFlags().StringVar(&cfg.HTTPUpstream, "target", "", "УСТАРЕЛО: используйте --http-upstream")
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
	copyIf("identity_file", func() { dst.SSHKeyFile = src.SSHKeyFile })
	copyIf("known-hosts", func() { dst.KnownHostsFile = src.KnownHostsFile })
	copyIf("insecure-host-key", func() { dst.InsecureHostKey = src.InsecureHostKey })
	copyIf("jump", func() { dst.JumpHosts = src.JumpHosts })
	copyIf("timeout", func() { dst.Timeout = src.Timeout })
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
	for index, arg := range os.Args[1:] {
		if arg == "--lang" && index+2 <= len(os.Args)-1 {
			language = os.Args[index+2]
		}
		if strings.HasPrefix(arg, "--lang=") {
			language = strings.TrimPrefix(arg, "--lang=")
		}
	}
	_ = i18n.Set(language)
}

func localizeCLI() {
	rootCmd.Short, rootCmd.Long = i18n.T(i18n.AppShort), i18n.T(i18n.AppLong)
	usages := map[string]i18n.ID{
		"config": i18n.FlagConfig, "lang": i18n.FlagLanguage, "install-service": i18n.FlagServiceInstall,
		"remove-service": i18n.FlagServiceRemove, "service-name": i18n.FlagServiceName, "service-user": i18n.FlagServiceUser,
		"service-group": i18n.FlagServiceGroup, "port": i18n.FlagSSHPort, "pass": i18n.FlagPassword,
		"identity_file": i18n.FlagIdentity, "known-hosts": i18n.FlagKnownHosts, "insecure-host-key": i18n.FlagInsecure,
		"jump": i18n.FlagJump, "timeout": i18n.FlagTimeout, "listen": i18n.FlagListen, "http": i18n.FlagHTTP,
		"socks5": i18n.FlagSOCKS, "sys-proxy": i18n.FlagSysProxy, "http-upstream": i18n.FlagUpstream,
		"tun": i18n.FlagTUN, "tun-global": i18n.FlagTUNGlobal, "tun-ip": i18n.FlagTUNIP,
		"tun-route": i18n.FlagTUNRoute, "tun-nat": i18n.FlagTUNNAT, "verbose": i18n.FlagVerbose,
		"log": i18n.FlagLog, "rules": i18n.FlagRules,
	}
	for name, id := range usages {
		if flag := rootCmd.Flags().Lookup(name); flag != nil {
			flag.Usage = i18n.T(id)
		}
	}
}

// parseSSHTarget parses an SSH target in user@host format.
func parseSSHTarget(target string) (string, string, error) {
	if target == "" {
		return "", "", nil
	}

	parts := strings.Split(target, "@")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("неверный формат SSH-цели, требуется формат user@host")
	}

	user := parts[0]
	host := parts[1]

	// Validate parsed values.
	if user == "" || host == "" {
		return "", "", fmt.Errorf("имя пользователя или хост не могут быть пустыми")
	}

	return user, host, nil
}

func addressWithDefaultPort(host, port string) (string, error) {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host, nil
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return net.JoinHostPort(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"), port), nil
	}
	if strings.Contains(host, ":") {
		return "", fmt.Errorf("неверный адрес SSH-сервера: %s", host)
	}
	return net.JoinHostPort(host, port), nil
}
