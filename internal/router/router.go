package router

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/zukhovich/ssh-tun/internal/i18n"
)

// Action defines a traffic routing action.
type Action string

const (
	ActionProxy  Action = "PROXY"  // Route through the proxy.
	ActionDirect Action = "DIRECT" // Connect directly.
	ActionReject Action = "REJECT" // Reject the connection.
)

// Mode defines a global routing mode.
type Mode string

const (
	ModeRule   Mode = "rule"   // Rule-based routing.
	ModeDirect Mode = "direct" // Route directly by default.
	ModeGlobal Mode = "global" // Route through the proxy by default.
)

// RuleType defines a routing rule type.
type RuleType string

const (
	DomainSuffix  RuleType = "DOMAIN-SUFFIX"  // Match a domain suffix.
	DomainKeyword RuleType = "DOMAIN-KEYWORD" // Match a keyword in a domain.
	Domain        RuleType = "DOMAIN"         // Match an exact domain.
	IPCIDR        RuleType = "IP-CIDR"        // Match an IPv4 subnet.
	IPCIDR6       RuleType = "IP-CIDR6"       // IPv6
	Match         RuleType = "MATCH"          // Match when no earlier rule applies.
)

// Rule represents one routing rule.
type Rule struct {
	Type    RuleType
	Payload string
	Target  Action
	network *net.IPNet
}

// Router matches hosts against ordered routing rules.
type Router struct {
	mode  Mode
	rules []Rule
}

// routerConfig represents the YAML rules document.
type routerConfig struct {
	Mode  Mode     `yaml:"mode"`
	Rules []string `yaml:"rules"`
}

// NewRouter loads routing rules from a YAML file.
func NewRouter(path string) (*Router, error) {
	if path == "" {
		return nil, errors.New(i18n.T("routing rules path must not be empty"))
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf(i18n.T("failed to read routing rules file: %w"), err)
	}

	var cfg routerConfig
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf(i18n.T("failed to parse the YAML routing rules file: %w"), err)
	}

	if cfg.Mode == "" {
		cfg.Mode = ModeRule
	}
	switch cfg.Mode {
	case ModeRule, ModeDirect, ModeGlobal:
	default:
		return nil, fmt.Errorf(i18n.T("unknown routing mode: %s"), cfg.Mode)
	}

	router := &Router{
		mode:  cfg.Mode,
		rules: make([]Rule, 0, len(cfg.Rules)),
	}

	for i, line := range cfg.Rules {
		parts := strings.Split(line, ",")
		for j := range parts {
			parts[j] = strings.TrimSpace(parts[j])
		}
		if len(parts) < 2 || len(parts) > 3 {
			return nil, fmt.Errorf(i18n.T("routing rules line %d has an invalid format"), i+1)
		}

		ruleType := RuleType(strings.ToUpper(parts[0]))
		switch ruleType {
		case DomainSuffix, DomainKeyword, Domain, IPCIDR, IPCIDR6, Match:
		default:
			return nil, fmt.Errorf(i18n.T("routing rules line %d contains an unknown rule type: %s"), i+1, parts[0])
		}
		if ruleType == Match {
			if len(parts) != 3 || parts[1] != "" {
				return nil, fmt.Errorf(i18n.T("routing rules line %d must use MATCH,,ACTION"), i+1)
			}
		} else if parts[1] == "" {
			return nil, fmt.Errorf(i18n.T("routing rules line %d contains an empty value"), i+1)
		}

		target := ActionProxy
		if len(parts) > 2 {
			switch strings.ToUpper(parts[2]) {
			case "PROXY":
				target = ActionProxy
			case "DIRECT":
				target = ActionDirect
			case "REJECT":
				target = ActionReject
			default:
				return nil, fmt.Errorf(i18n.T("routing rules line %d contains an unknown action: %s"), i+1, parts[2])
			}
		}
		payload := strings.ToLower(strings.TrimSuffix(parts[1], "."))
		rule := Rule{
			Type:    ruleType,
			Payload: payload,
			Target:  target,
		}
		if ruleType == IPCIDR || ruleType == IPCIDR6 {
			_, network, err := net.ParseCIDR(payload)
			if err != nil {
				return nil, fmt.Errorf(i18n.T("routing rules line %d contains an invalid CIDR: %w"), i+1, err)
			}
			if (ruleType == IPCIDR) != (network.IP.To4() != nil) {
				return nil, fmt.Errorf(i18n.T("routing rules line %d contains a CIDR of the wrong IP version"), i+1)
			}
			rule.network = network
		}
		router.rules = append(router.rules, rule)
	}
	return router, nil
}

// Match returns the routing action for a host.
func (r *Router) Match(host string) Action {
	switch r.mode {
	case ModeGlobal:
		return ActionProxy
	case ModeDirect:
		return ActionDirect
	}

	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}

	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	ip := net.ParseIP(hostname)
	for _, rule := range r.rules {
		match := false
		switch rule.Type {
		case DomainSuffix:
			match = hostname == rule.Payload || strings.HasSuffix(hostname, "."+rule.Payload)
		case DomainKeyword:
			match = strings.Contains(hostname, rule.Payload)
		case Domain:
			match = hostname == rule.Payload
		case IPCIDR, IPCIDR6:
			match = ip != nil && rule.network.Contains(ip)
		case Match:
			match = true
		}

		if match {
			return rule.Target
		}
	}

	return ActionProxy
}
