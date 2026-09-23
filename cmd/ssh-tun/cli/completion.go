package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/zukhovich/ssh-tun/internal/config"
	"github.com/zukhovich/ssh-tun/internal/i18n"
)

func newCompletionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:       "completion [bash|zsh|fish|powershell]",
		Short:     i18n.T("Generate shell completion script"),
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return rootCmd.GenBashCompletion(cmd.OutOrStdout())
			case "zsh":
				return rootCmd.GenZshCompletion(cmd.OutOrStdout())
			case "fish":
				return rootCmd.GenFishCompletion(cmd.OutOrStdout(), true)
			case "powershell":
				return rootCmd.GenPowerShellCompletionWithDesc(cmd.OutOrStdout())
			default:
				return fmt.Errorf(i18n.T("unsupported shell: %s"), args[0])
			}
		},
	}
	return cmd
}

func registerCompletions() {
	rootCmd.ValidArgsFunction = completeSSHTargets
	_ = rootCmd.RegisterFlagCompletionFunc("config", completeFiles("yaml", "yml"))
	_ = rootCmd.RegisterFlagCompletionFunc("write-config", completeFiles("yaml", "yml"))
	_ = rootCmd.RegisterFlagCompletionFunc("identity-file", completeFiles())
	_ = rootCmd.RegisterFlagCompletionFunc("known-hosts", completeFiles())
	_ = rootCmd.RegisterFlagCompletionFunc("ssh-config", completeFiles())
	_ = rootCmd.RegisterFlagCompletionFunc("rules", completeFiles("yaml", "yml"))
	_ = rootCmd.RegisterFlagCompletionFunc("install-service", fixedCompletion("auto", "systemd", "openrc", "windows"))
	_ = rootCmd.RegisterFlagCompletionFunc("remove-service", fixedCompletion("auto", "systemd", "openrc", "windows"))
}

func completeSSHTargets(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	aliases, err := config.SSHConfigAliases(cfg.SSHConfigFile)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var matches []string
	for _, alias := range aliases {
		if strings.HasPrefix(alias, toComplete) {
			matches = append(matches, alias)
		}
	}
	return matches, cobra.ShellCompDirectiveNoFileComp
}

func fixedCompletion(values ...string) cobra.CompletionFunc {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		var matches []string
		for _, value := range values {
			if strings.HasPrefix(value, toComplete) {
				matches = append(matches, value)
			}
		}
		return matches, cobra.ShellCompDirectiveNoFileComp
	}
}

func completeFiles(extensions ...string) cobra.CompletionFunc {
	allowed := make(map[string]struct{}, len(extensions))
	for _, extension := range extensions {
		allowed["."+extension] = struct{}{}
	}
	return func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		dir, base := filepath.Split(toComplete)
		searchDir := dir
		if searchDir == "" {
			searchDir = "."
		}
		entries, err := os.ReadDir(searchDir)
		if err != nil {
			return nil, cobra.ShellCompDirectiveDefault
		}
		var matches []string
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), base) {
				continue
			}
			candidate := filepath.Join(dir, entry.Name())
			if entry.IsDir() {
				matches = append(matches, candidate+string(os.PathSeparator))
				continue
			}
			if len(allowed) == 0 {
				matches = append(matches, candidate)
				continue
			}
			if _, ok := allowed[strings.ToLower(filepath.Ext(entry.Name()))]; ok {
				matches = append(matches, candidate)
			}
		}
		return matches, cobra.ShellCompDirectiveNoSpace
	}
}
