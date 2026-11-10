package main

// Application core: admission/status HTTP services, derper argument assembly,
// tiered SIGHUP reload, external certificate watching, and the serve subcommand.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// admitRequest matches the serialization format of upstream
// tailcfg.DERPAdmitClientRequest (capitalized field names, no json tags).
type admitRequest struct {
	NodePublic string `json:"NodePublic"` // "nodekey:<64 hex chars>"
	Source     string `json:"Source"`     // DERP client source IP
}

type admitResponse struct {
	Allow bool `json:"Allow"`
}

type app struct {
	cfgPath string
	cfg     *Config
	guard   *Guard
	sup     *supervisor

	admitPort int

	mu              sync.Mutex
	certFingerprint string // self-signed mode "sha256-raw:..." fingerprint
	stagedHash      string // content hash of the currently staged external certificate

	stunServer *stunServer
}

// derperArgs assembles the full derper child command line from current config.
func (a *app) derperArgs(admitPort int) []string {
	d := &a.cfg.Derper
	args := []string{
		"--a=" + d.ListenAddr,
	}
	switch d.STUNMode {
	case "embedded", "disabled":
		args = append(args, "--stun=false")
	case "derper":
		args = append(args, "--stun-port="+strconv.Itoa(d.STUNPort))
	}
	if d.Home != "" {
		args = append(args, "--home="+d.Home)
	}
	args = append(args,
		"--verify-client-url=http://127.0.0.1:"+strconv.Itoa(admitPort)+"/admit",
		"--verify-client-url-fail-open=false",
	)
	switch d.CertMode {
	case "reverse_proxy":
		// On a non-443 port with a non-manual certmode, upstream derper's
		// serveTLS is false and it serves plain HTTP; TLS is terminated by the
		// Caddy/Nginx reverse proxy in front.
		args = append(args, "--certmode=letsencrypt", "--http-port=-1", "--hostname="+d.Hostname)
	case "derper_selfsigned":
		// certmode=manual with an IP hostname: derper auto-generates a
		// self-signed cert and prints the CertName fingerprint.
		args = append(args, "--certmode=manual", "--certdir="+d.CertDir, "--hostname="+d.Hostname, "--http-port=-1")
	case "derper_letsencrypt":
		args = append(args, "--certmode=letsencrypt", "--certdir="+d.CertDir, "--hostname="+d.Hostname, "--http-port="+strconv.Itoa(d.HTTPPort))
	case "custom_selfsigned", "external_letsencrypt":
		args = append(args, "--certmode=manual", "--certdir="+d.CertDir, "--hostname="+d.Hostname, "--http-port="+strconv.Itoa(d.HTTPPort))
	}
	args = append(args, d.ExtraFlags...)
	return args
}

func (a *app) handleAdmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req admitRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&req); err != nil {
		log.Printf("[ADMIT] WARN failed to decode admit request: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(admitResponse{Allow: false})
		return
	}
	allow := a.guard.Verify(req.NodePublic, req.Source)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(admitResponse{Allow: allow})
}

func (a *app) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.mu.Lock()
	fp := a.certFingerprint
	stunSrv := a.stunServer
	a.mu.Unlock()
	var pid int
	if a.sup != nil {
		pid = a.sup.currentPID()
	}
	snap := a.guard.StatusSnapshot(fp, pid)
	snap["stun_mode"] = a.cfg.Derper.STUNMode
	if stunSrv != nil {
		snap["stun_listen"] = stunSrv.Addr()
		snap["stun_packets_rx"] = stunSrv.rxPackets.Load()
		snap["stun_packets_tx"] = stunSrv.txPackets.Load()
	} else if a.cfg.Derper.STUNMode == "derper" {
		snap["stun_listen"] = fmt.Sprintf("derper:%d", a.cfg.Derper.STUNPort)
	} else {
		snap["stun_listen"] = "disabled"
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(snap)
}

// reloadConfig handles SIGHUP: on parse errors the current state is kept; the
// [guard] section is always hot-updated (plus an async sync); the child process
// is only restarted when the [derper] section changed (or, for external cert
// modes, the cert file content changed).
func (a *app) reloadConfig() {
	newCfg, err := loadConfig(a.cfgPath)
	if err != nil {
		log.Printf("[RELOAD] ERROR failed to reload config, keeping current state: %v", err)
		return
	}
	old := a.cfg

	derperChanged := !reflect.DeepEqual(old.Derper, newCfg.Derper)
	stunChanged := old.Derper.STUNMode != newCfg.Derper.STUNMode ||
		old.Derper.STUNListen != newCfg.Derper.STUNListen ||
		old.Derper.STUNPort != newCfg.Derper.STUNPort
	certChanged := false
	if m := newCfg.Derper.CertMode; m == "custom_selfsigned" || m == "external_letsencrypt" {
		if h, err := certFileHash(newCfg.Derper.CertFile, newCfg.Derper.KeyFile); err == nil {
			a.mu.Lock()
			certChanged = h != a.stagedHash
			a.mu.Unlock()
		}
	}

	// The [guard] section is always hot-updated, then synced once asynchronously.
	a.guard.UpdateConfig(newCfg.Guard)
	go a.guard.SyncAll(context.Background())

	if stunChanged {
		log.Printf("[RELOAD] STUN configuration changed (mode=%s), updating STUN server", newCfg.Derper.STUNMode)
		a.stopSTUN()
		if newCfg.Derper.STUNMode == "embedded" && newCfg.Derper.STUNListen != "" {
			if err := a.startSTUN(newCfg.Derper.STUNListen); err != nil {
				log.Printf("[STUN] WARN failed to restart STUN server on %s: %v", newCfg.Derper.STUNListen, err)
			}
		}
	}

	if !derperChanged && !certChanged {
		a.cfg = newCfg
		log.Printf("[RELOAD] guard config reloaded without restarting derper")
		return
	}

	if m := newCfg.Derper.CertMode; m == "custom_selfsigned" || m == "external_letsencrypt" {
		h, err := stageAndValidateCert(&newCfg.Derper)
		if err != nil {
			log.Printf("[RELOAD] WARN cert validation failed, keeping derper on its current config: %v", err)
			return
		}
		a.mu.Lock()
		a.stagedHash = h
		a.mu.Unlock()
	}
	a.cfg = newCfg
	log.Printf("[RELOAD] [derper] config or cert changed, gracefully restarting derper")
	a.sup.restart(a.derperArgs(a.admitPort))
}

// watchCertFiles monitors external cert file content hashes in the background;
// on change it restarts derper to load the new certificate, but only if
// validation passes. A failed validation (e.g. the external tool wrote the cert
// but not yet the key) only logs a warning and leaves the running derper alone.
func (a *app) watchCertFiles(ctx context.Context) {
	interval := time.Duration(a.cfg.Derper.CertCheckIntervalSec) * time.Second
	if interval <= 0 {
		interval = 60 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d := &a.cfg.Derper
			h, err := certFileHash(d.CertFile, d.KeyFile)
			if err != nil {
				log.Printf("[CERT] WARN failed to read cert files: %v", err)
				continue
			}
			a.mu.Lock()
			staged := a.stagedHash
			a.mu.Unlock()
			if h == staged {
				continue
			}
			log.Printf("[CERT] cert file change detected, validating")
			newHash, err := stageAndValidateCert(&a.cfg.Derper)
			if err != nil {
				log.Printf("[CERT] WARN cert validation failed, keeping current cert: %v", err)
				continue
			}
			a.mu.Lock()
			a.stagedHash = newHash
			a.mu.Unlock()
			log.Printf("[CERT] cert validated, restarting derper to load the new certificate")
			a.sup.restart(a.derperArgs(a.admitPort))
		}
	}
}

// captureSelfSignedFingerprint extracts the self-signed cert fingerprint 2
// seconds after derper starts, logs it, and exposes it via the cert_sha256_raw
// field of /status.
func (a *app) captureSelfSignedFingerprint() {
	time.Sleep(2 * time.Second)
	crtPath, _ := derperCertPaths(a.cfg.Derper.CertDir, a.cfg.Derper.Hostname)
	fp, err := extractCertRawSHA256(crtPath)
	if err != nil {
		log.Printf("[CERT] WARN failed to extract self-signed cert fingerprint (derper may not have generated it yet): %v", err)
		return
	}
	a.mu.Lock()
	a.certFingerprint = fp
	a.mu.Unlock()
	log.Printf("[CERT] self-signed cert fingerprint (use as CertName in ACL derpMap): %s", fp)
}

// ============================================================================
// serve subcommand
// ============================================================================

func cmdServe(configPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	a := &app{cfgPath: configPath, cfg: cfg}
	a.guard = newGuard(cfg.Guard)
	log.Printf("[MAIN] derp-guard starting, config: %s (cert_mode=%s)", configPath, cfg.Derper.CertMode)

	// 1. Load the on-disk node cache snapshot (a Tailscale API outage right
	//    after a restart must not deadlock us with an empty table).
	a.guard.LoadCache(cfg.Guard.CacheFile)

	// 2. Concurrently fetch every friend's device list and build the table.
	a.guard.SyncAll(context.Background())

	// 3. Start the internal admission service (127.0.0.1:0, kernel-assigned
	//    port) and the status service.
	admitLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to start admission listener: %w", err)
	}
	a.admitPort = admitLn.Addr().(*net.TCPAddr).Port
	admux := http.NewServeMux()
	admux.HandleFunc("/admit", a.handleAdmit)
	go func() {
		if err := (&http.Server{Handler: admux}).Serve(admitLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[ADMIT] WARN admission HTTP server exited unexpectedly: %v", err)
		}
	}()
	log.Printf("[MAIN] admission endpoint ready: http://127.0.0.1:%d/admit", a.admitPort)

	if cfg.Guard.StatusListen != "" {
		stMux := http.NewServeMux()
		stMux.HandleFunc("/status", a.handleStatus)
		stLn, err := net.Listen("tcp", cfg.Guard.StatusListen)
		if err != nil {
			return fmt.Errorf("failed to start status listener: %w", err)
		}
		go func() {
			if err := (&http.Server{Handler: stMux}).Serve(stLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("[STATUS] WARN status HTTP server exited unexpectedly: %v", err)
			}
		}()
		log.Printf("[MAIN] status endpoint ready: http://%s/status", cfg.Guard.StatusListen)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.guard.pollLoop(ctx)

	// 4. Prepare cert directories per cert mode, spawn and supervise derper.
	d := &cfg.Derper
	if err := os.MkdirAll(d.CertDir, 0700); err != nil {
		return fmt.Errorf("failed to create cert_dir: %w", err)
	}
	switch d.CertMode {
	case "custom_selfsigned", "external_letsencrypt":
		h, err := stageAndValidateCert(&cfg.Derper)
		if err != nil {
			return fmt.Errorf("cert validation failed: %w", err)
		}
		a.mu.Lock()
		a.stagedHash = h
		a.mu.Unlock()
		go a.watchCertFiles(ctx)
	}

	a.sup = newSupervisor(d.BinPath, a.derperArgs(a.admitPort))
	a.sup.start()

	if d.CertMode == "derper_selfsigned" || d.CertMode == "custom_selfsigned" {
		go a.captureSelfSignedFingerprint()
	}

	// 5. Embedded STUN server (when stun_mode == "embedded")
	if d.STUNMode == "embedded" && d.STUNListen != "" {
		if err := a.startSTUN(d.STUNListen); err != nil {
			log.Printf("[STUN] WARN failed to start embedded STUN server on %s: %v", d.STUNListen, err)
		}
	}

	// Signals: SIGHUP tiered reload; SIGINT/SIGTERM graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	for {
		sig := <-sigCh
		switch sig {
		case syscall.SIGHUP:
			log.Printf("[MAIN] received SIGHUP, reloading config: %s", configPath)
			a.reloadConfig()
		case syscall.SIGINT, syscall.SIGTERM:
			log.Printf("[MAIN] received %v, shutting down gracefully", sig)
			cancel()
			a.stopSTUN()
			a.sup.shutdown()
			return nil
		}
	}
}

func (a *app) startSTUN(addr string) error {
	s, err := newSTUNServer(addr)
	if err != nil {
		return err
	}
	s.start()
	a.mu.Lock()
	a.stunServer = s
	a.mu.Unlock()
	return nil
}

func (a *app) stopSTUN() {
	a.mu.Lock()
	s := a.stunServer
	a.stunServer = nil
	a.mu.Unlock()
	if s != nil {
		s.stop()
	}
}
