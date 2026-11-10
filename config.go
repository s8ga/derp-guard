package main

// Config file parsing and validation (TOML; the only third-party dependency
// is github.com/BurntSushi/toml).

import (
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
)

// DerperConfig maps to the [derper] section of the config file.
type DerperConfig struct {
	BinPath    string   `toml:"bin_path"`
	Hostname   string   `toml:"hostname"`
	ListenAddr string   `toml:"listen_addr"`
	HTTPPort   int      `toml:"http_port"` // -1 disables port 80; set to 80 for derper_letsencrypt
	STUNMode   string   `toml:"stun_mode"` // "embedded" (default), "derper", "disabled"
	STUNPort   int      `toml:"stun_port"` // STUN port for derpMap; -1 disables STUN; defaults to 3478
	STUNListen string   `toml:"stun_listen"` // optional: STUN UDP listen address for embedded mode (defaults to ":<stun_port>")
	Home       string   `toml:"home"` // passed to derper --home: "blank" hides the fingerprint page; a URL redirects; empty means "do not pass"
	CertDir    string   `toml:"cert_dir"`
	IPv4       string   `toml:"ipv4"`       // optional: explicit IPv4 emitted by the derpmap subcommand
	ExtraFlags []string `toml:"extra_flags"` // optional: extra CLI flags passed through to derper

	// Certificate / run mode (choose exactly one):
	//   reverse_proxy        - plain HTTP locally; a Caddy/Nginx reverse proxy terminates TLS
	//   derper_selfsigned    - derper auto-generates a self-signed IP cert (hostname must be a public IP)
	//   custom_selfsigned    - user-provided single self-signed certificate (cert_file/key_file)
	//   derper_letsencrypt   - derper's built-in ACME (needs a public domain and ports 80/443)
	//   external_letsencrypt - external certbot/acme.sh managed certs (cert_file/key_file)
	CertMode             string `toml:"cert_mode"`
	CertFile             string `toml:"cert_file"`
	KeyFile              string `toml:"key_file"`
	CertCheckIntervalSec int    `toml:"cert_check_interval_sec"`
}

// Friend maps to one [[guard.friends]] array entry.
type Friend struct {
	Name         string `toml:"name"`
	ClientID     string `toml:"client_id"`
	ClientSecret string `toml:"client_secret"`
}

// GuardConfig maps to the [guard] section.
type GuardConfig struct {
	PollIntervalSec int               `toml:"poll_interval_sec"`
	MissCooldownSec int               `toml:"miss_cooldown_sec"`
	RevokeOnAuthErr bool              `toml:"revoke_on_auth_err"`
	StatusListen    string            `toml:"status_listen"`
	CacheFile       string            `toml:"cache_file"`
	StaticNodes     map[string]string `toml:"static_nodes"` // emergency static allowlist: "nodekey:64hex" = "device note"
	Friends         []Friend          `toml:"friends"`
}

// Config is the root of the config file.
type Config struct {
	Derper DerperConfig `toml:"derper"`
	Guard  GuardConfig  `toml:"guard"`
}

var validCertModes = map[string]bool{
	"reverse_proxy":        true,
	"derper_selfsigned":    true,
	"custom_selfsigned":    true,
	"derper_letsencrypt":   true,
	"external_letsencrypt": true,
}

func loadConfig(path string) (*Config, error) {
	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	d := &cfg.Derper
	if d.CertMode == "" || !validCertModes[d.CertMode] {
		return nil, fmt.Errorf("[derper] invalid cert_mode %q: must be one of reverse_proxy / derper_selfsigned / custom_selfsigned / derper_letsencrypt / external_letsencrypt", d.CertMode)
	}
	if d.Hostname == "" {
		return nil, fmt.Errorf("[derper] hostname must not be empty")
	}
	if d.BinPath == "" {
		d.BinPath = "/usr/libexec/derper"
	}
	if d.ListenAddr == "" {
		d.ListenAddr = ":443"
	}
	if d.STUNPort == 0 {
		d.STUNPort = 3478
	}
	if d.STUNPort < 0 {
		d.STUNMode = "disabled"
	}
	if d.STUNMode == "" {
		d.STUNMode = "embedded"
	}
	if d.STUNMode != "embedded" && d.STUNMode != "derper" && d.STUNMode != "disabled" {
		return nil, fmt.Errorf("[derper] invalid stun_mode %q: must be one of embedded / derper / disabled", d.STUNMode)
	}
	if d.STUNMode == "embedded" && d.STUNListen == "" {
		d.STUNListen = fmt.Sprintf(":%d", d.STUNPort)
	}
	if d.HTTPPort == 0 {
		d.HTTPPort = -1
	}
	if d.CertDir == "" {
		d.CertDir = "/var/lib/derp-guard/certs"
	}
	if d.CertCheckIntervalSec <= 0 {
		d.CertCheckIntervalSec = 60
	}
	if d.CertMode == "reverse_proxy" {
		// Upstream derper force-enables TLS on port 443
		// (serveTLS := IsProd443(addr) || certmode==manual), so the plain-HTTP
		// reverse-proxy mode must listen on a non-443 port (e.g. 127.0.0.1:3340).
		if strings.HasSuffix(d.ListenAddr, ":443") {
			return nil, fmt.Errorf("[derper] cert_mode=\"reverse_proxy\" requires listen_addr on a non-443 port (e.g. 127.0.0.1:3340), got %q", d.ListenAddr)
		}
	}
	if d.CertMode == "custom_selfsigned" || d.CertMode == "external_letsencrypt" {
		if d.CertFile == "" || d.KeyFile == "" {
			return nil, fmt.Errorf("[derper] cert_mode=%q requires both cert_file and key_file to be set", d.CertMode)
		}
	}

	g := &cfg.Guard
	if g.PollIntervalSec <= 0 {
		g.PollIntervalSec = 300
	}
	if g.MissCooldownSec <= 0 {
		g.MissCooldownSec = 60
	}
	return &cfg, nil
}
