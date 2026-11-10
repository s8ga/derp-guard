package main

// derpmap subcommand: prints a derpMap JSON snippet for friends to paste into
// their Tailscale ACL policy.

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

const derpMapRegionID = 900

func regionCodeFromHostname(hostname string) string {
	label := strings.SplitN(strings.ToLower(hostname), ".", 2)[0]
	label = unsafeHostnameCharacters.ReplaceAllString(label, "")
	label = strings.ReplaceAll(label, ".", "")
	if label == "" {
		label = "myderp"
	}
	return label
}

func cmdDerpMap(configPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	d := &cfg.Derper

	node := map[string]any{
		"Name":     "1",
		"RegionID": derpMapRegionID,
		"HostName": d.Hostname,
	}
	if d.STUNMode != "disabled" && d.STUNPort > 0 {
		node["STUNPort"] = d.STUNPort
	}
	if d.IPv4 != "" {
		// Explicit IPv4 with IPv6 disabled, so clients skip AAAA DNS lookups.
		node["IPv4"] = d.IPv4
		node["IPv6"] = "none"
	}
	switch d.CertMode {
	case "derper_selfsigned", "custom_selfsigned":
		crtPath, _ := derperCertPaths(d.CertDir, d.Hostname)
		fp, err := extractCertRawSHA256(crtPath)
		if err != nil {
			return fmt.Errorf("self-signed cert modes need an existing cert file %s to generate derpMap (run `derp-guard serve` once first): %w", crtPath, err)
		}
		node["CertName"] = fp
	}

	derpMap := map[string]any{
		"Regions": map[string]any{
			strconv.Itoa(derpMapRegionID): map[string]any{
				"RegionID":   derpMapRegionID,
				"RegionCode": regionCodeFromHostname(d.Hostname),
				"RegionName": "derp-guard " + d.Hostname,
				"Nodes":      []any{node},
			},
		},
	}
	out, err := json.MarshalIndent(derpMap, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	fmt.Println()
	fmt.Println(`# Usage: paste the JSON object above as the "derpMap" field of your Tailscale`)
	fmt.Println(`#        ACL policy (https://login.tailscale.com/admin/acls); every tailnet`)
	fmt.Println(`#        member can then use this DERP node.`)
	fmt.Println(`#        Self-signed modes get the sha256-raw fingerprint filled in as`)
	fmt.Println(`#        CertName automatically; with ipv4 configured, "IPv6": "none" is added.`)
	return nil
}
