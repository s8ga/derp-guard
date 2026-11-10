package main

// Guard: OAuth sync and three-tier admission control.
//
// Each friend (tailnet) has its own cached OAuth token; SyncAll fetches every
// tailnet's device list concurrently; credential revocation and transient
// errors are handled per-friend. Admission checks are three-tier:
// allow table -> negative cache (instant deny) -> forced sync after cooldown.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	tailscaleTokenURL   = "https://api.tailscale.com/api/v2/oauth/token"
	tailscaleDevicesURL = "https://api.tailscale.com/api/v2/tailnet/-/devices"
	tokenExpirySlack    = 300 * time.Second // safety margin subtracted from token lifetime
	perFriendTimeout    = 8 * time.Second   // per-request timeout for a single friend's API call
)

// NodeMeta describes one admitted device (used for logs and /status).
type NodeMeta struct {
	Friend string `json:"friend"`
	Device string `json:"device"`
	User   string `json:"user"`
}

type cachedToken struct {
	token  string
	expiry time.Time
}

// authError is a credential-revocation class error (invalid/revoked OAuth client).
type authError struct{ msg string }

func (e *authError) Error() string { return e.msg }

// transientError is a transient network/server error (timeout, DNS, 429/5xx, ...).
type transientError struct{ msg string }

func (e *transientError) Error() string { return e.msg }

// deviceJSON decodes only the fields of the Tailscale device list we care about.
type deviceJSON struct {
	NodeKey    string `json:"nodeKey"`
	Hostname   string `json:"hostname"`
	User       string `json:"user"`
	Authorized bool   `json:"authorized"`
	IsExternal bool   `json:"isExternal"`
}

type devicesResp struct {
	Devices []deviceJSON `json:"devices"`
}

type tokenResp struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// Guard maintains the cross-tailnet admission table.
type Guard struct {
	mu               sync.RWMutex // protects every field below
	cfg              GuardConfig  // currently effective [guard] config (hot-reloaded on SIGHUP)
	client           *http.Client // 8s per-request timeout
	tokens           map[string]*cachedToken
	byFriend         map[string]map[string]NodeMeta // friend name -> nodekey -> meta
	synced           map[string]bool                // friend name -> whether synced at least once
	nodes            map[string]NodeMeta            // global read-only table (friends + static allowlist)
	negCache         map[string]time.Time           // negative cache: nodekey -> deny-until
	lastSync         time.Time
	lastForceSync    time.Time
	tableInitialized bool
	startedAt        time.Time

	syncMu sync.Mutex // serializes SyncAll so polling and forced syncs cannot interleave
}

func newGuard(cfg GuardConfig) *Guard {
	return &Guard{
		cfg:       cfg,
		client:    &http.Client{Timeout: perFriendTimeout},
		tokens:    map[string]*cachedToken{},
		byFriend:  map[string]map[string]NodeMeta{},
		synced:    map[string]bool{},
		nodes:     map[string]NodeMeta{},
		negCache:  map[string]time.Time{},
		startedAt: time.Now(),
	}
}

func nodesEqual(a, b map[string]NodeMeta) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok || va != vb {
			return false
		}
	}
	return true
}

// UpdateConfig hot-swaps the [guard] config (SIGHUP): replaces the friend list,
// static allowlist and settings, keeping snapshots and tokens of friends that
// still exist, then rebuilds the global admission table immediately.
func (g *Guard) UpdateConfig(nc GuardConfig) {
	g.mu.Lock()
	g.cfg = nc
	keep := make(map[string]bool, len(nc.Friends))
	for _, f := range nc.Friends {
		keep[f.Name] = true
	}
	for name := range g.byFriend {
		if !keep[name] {
			delete(g.byFriend, name)
		}
	}
	for name := range g.tokens {
		if !keep[name] {
			delete(g.tokens, name)
		}
	}
	for name := range g.synced {
		if !keep[name] {
			delete(g.synced, name)
		}
	}
	g.negCache = map[string]time.Time{}
	g.mu.Unlock()
	g.rebuildAndPersist(true)
}

// token fetches (and caches) a friend's API access token.
func (g *Guard) token(ctx context.Context, f Friend) (string, error) {
	g.mu.RLock()
	t := g.tokens[f.Name]
	g.mu.RUnlock()
	if t != nil && time.Now().Before(t.expiry) {
		return t.token, nil
	}

	rctx, cancel := context.WithTimeout(ctx, perFriendTimeout)
	defer cancel()
	form := url.Values{
		"client_id":     {f.ClientID},
		"client_secret": {f.ClientSecret},
		"grant_type":    {"client_credentials"},
		"scope":         {"devices:core:read"},
	}
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, tailscaleTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", &transientError{msg: err.Error()}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := g.client.Do(req)
	if err != nil {
		return "", &transientError{msg: fmt.Sprintf("failed to request OAuth token: %v", err)}
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized:
		return "", &authError{msg: fmt.Sprintf("token endpoint returned HTTP %d (OAuth client credentials invalid or revoked)", resp.StatusCode)}
	default:
		return "", &transientError{msg: fmt.Sprintf("token endpoint returned HTTP %d", resp.StatusCode)}
	}
	var tr tokenResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil || tr.AccessToken == "" {
		return "", &transientError{msg: fmt.Sprintf("failed to decode token response: %v", err)}
	}
	expiry := time.Now().Add(time.Duration(tr.ExpiresIn)*time.Second - tokenExpirySlack)
	g.mu.Lock()
	g.tokens[f.Name] = &cachedToken{token: tr.AccessToken, expiry: expiry}
	g.mu.Unlock()
	log.Printf("[GUARD] friend %q obtained a new API token (valid until %s)", f.Name, expiry.Format(time.RFC3339))
	return tr.AccessToken, nil
}

// fetchDevicesOnce fetches the device list once with the current token.
func (g *Guard) fetchDevicesOnce(ctx context.Context, f Friend) ([]deviceJSON, error) {
	tok, err := g.token(ctx, f)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tailscaleDevicesURL, nil)
	if err != nil {
		return nil, &transientError{msg: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, &transientError{msg: fmt.Sprintf("failed to fetch device list: %v", err)}
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusBadRequest:
		return nil, &authError{msg: fmt.Sprintf("device list request returned HTTP %d (invalid token)", resp.StatusCode)}
	default:
		return nil, &transientError{msg: fmt.Sprintf("device list request returned HTTP %d", resp.StatusCode)}
	}
	var out devicesResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&out); err != nil {
		return nil, &transientError{msg: fmt.Sprintf("failed to decode device list: %v", err)}
	}
	return out.Devices, nil
}

// fetchFriendDevices fetches a friend's device list; on 401 it drops the cached
// token and retries once before declaring a credential-revocation error.
func (g *Guard) fetchFriendDevices(ctx context.Context, f Friend) ([]deviceJSON, error) {
	devs, err := g.fetchDevicesOnce(ctx, f)
	if err == nil {
		return devs, nil
	}
	var ae *authError
	if errors.As(err, &ae) {
		g.mu.Lock()
		delete(g.tokens, f.Name) // drop the cached token, force a fresh exchange
		g.mu.Unlock()
		rctx, cancel := context.WithTimeout(ctx, perFriendTimeout)
		defer cancel()
		return g.fetchDevicesOnce(rctx, f)
	}
	return nil, err
}

// SyncAll fetches all friends' device lists concurrently and rebuilds the
// global admission table. Errors are isolated per friend: credential
// revocation (with revoke_on_auth_err) clears that friend's nodes; transient
// errors keep the last successful snapshot so online friends are never locked
// out by a bad API day.
//
// Returns true iff every configured friend synced without transient errors.
func (g *Guard) SyncAll(ctx context.Context) bool {
	g.syncMu.Lock()
	defer g.syncMu.Unlock()

	g.mu.RLock()
	friends := g.cfg.Friends
	revoke := g.cfg.RevokeOnAuthErr
	g.mu.RUnlock()

	var transientFailed atomic.Bool
	var wg sync.WaitGroup
	for _, f := range friends {
		wg.Add(1)
		go func(f Friend) {
			defer wg.Done()
			devs, err := g.fetchFriendDevices(ctx, f)
			g.mu.Lock()
			defer g.mu.Unlock()
			if err != nil {
				var ae *authError
				if errors.As(err, &ae) && revoke {
					log.Printf("[GUARD] WARN friend %q credentials revoked, clearing its nodes per config: %v", f.Name, err)
					g.byFriend[f.Name] = map[string]NodeMeta{}
					delete(g.synced, f.Name)
				} else {
					transientFailed.Store(true)
					log.Printf("[GUARD] friend %q sync failed (transient), keeping last snapshot: %v", f.Name, err)
				}
				return
			}
			m := make(map[string]NodeMeta, len(devs))
			for _, d := range devs {
				// Strict filtering: drop devices without a node key, unauthorized
				// devices, and external devices shared in via Node Sharing.
				if d.NodeKey == "" || !d.Authorized || d.IsExternal {
					continue
				}
				m[d.NodeKey] = NodeMeta{Friend: f.Name, Device: d.Hostname, User: d.User}
			}
			changed := !g.synced[f.Name] || !nodesEqual(g.byFriend[f.Name], m)
			g.byFriend[f.Name] = m
			g.synced[f.Name] = true
			if changed {
				log.Printf("[GUARD] friend %q sync complete: %d devices, %d admitted", f.Name, len(devs), len(m))
			}
		}(f)
	}
	wg.Wait()

	g.mu.Lock()
	g.lastSync = time.Now()
	g.mu.Unlock()

	g.rebuildAndPersist(false)
	return !transientFailed.Load() && ctx.Err() == nil
}

// rebuildAndPersist merges friend snapshots with the static allowlist into the
// global read-only table, expires stale negative-cache entries, and atomically
// writes the disk snapshot when the admitted table changed (or force is true).
func (g *Guard) rebuildAndPersist(force bool) {
	g.mu.Lock()
	merged := make(map[string]NodeMeta)
	for _, fm := range g.byFriend {
		for k, v := range fm {
			merged[k] = v
		}
	}
	for k, note := range g.cfg.StaticNodes {
		if _, ok := merged[k]; !ok {
			merged[k] = NodeMeta{Friend: "static", Device: note, User: "-"}
		}
	}
	now := time.Now()
	for k, exp := range g.negCache {
		if !now.Before(exp) {
			delete(g.negCache, k)
		} else if _, ok := merged[k]; ok {
			delete(g.negCache, k)
		}
	}
	changed := force || !g.tableInitialized || !nodesEqual(g.nodes, merged)
	g.nodes = merged
	g.tableInitialized = true
	cacheFile := g.cfg.CacheFile
	var cacheData []byte
	var marshalErr error
	if changed && cacheFile != "" {
		// Marshal under g.mu so concurrent writers cannot mutate byFriend mid-iteration.
		cacheData, marshalErr = json.MarshalIndent(&nodeCacheFile{SavedAt: now.UTC(), ByFriend: g.byFriend}, "", "  ")
	}
	g.mu.Unlock()

	if !changed {
		return
	}
	log.Printf("[GUARD] admission table updated: %d nodes total", len(merged))
	if cacheFile != "" {
		if marshalErr != nil {
			log.Printf("[GUARD] WARN failed to marshal node cache snapshot: %v", marshalErr)
		} else if err := writeCacheBytes(cacheFile, cacheData); err != nil {
			log.Printf("[GUARD] WARN failed to write node cache snapshot: %v", err)
		}
	}
}

// Verify is the three-tier admission check:
//  1. hit in the allow table -> admit;
//  2. hit in the negative cache (not expired) -> instant deny, no API calls;
//  3. cache miss: if the miss cooldown has elapsed, force one sync (4.5s cap) and
//     re-check; still missing after a clean sync -> add to negative cache
//     (TTL = poll_interval_sec) and deny. Transient sync errors deny without
//     writing the negative cache.
func (g *Guard) Verify(nodeKey, sourceIP string) bool {
	g.mu.RLock()
	meta, allowed := g.nodes[nodeKey]
	negExp, negCached := g.negCache[nodeKey]
	cooldown := time.Duration(g.cfg.MissCooldownSec) * time.Second
	g.mu.RUnlock()

	if allowed {
		log.Printf("[ADMIT] ALLOW friend=%s device=%s user=%s ip=%s key=%s", meta.Friend, meta.Device, meta.User, sourceIP, nodeKey)
		return true
	}
	now := time.Now()
	if negCached && now.Before(negExp) {
		log.Printf("[ADMIT] DENY (neg-cached) ip=%s key=%s", sourceIP, nodeKey)
		return false
	}

	// Tier 3: cache-miss cooldown with immediate sync.
	g.mu.Lock()
	if time.Since(g.lastForceSync) < cooldown {
		g.mu.Unlock()
		log.Printf("[ADMIT] DENY (miss-cooldown) ip=%s key=%s", sourceIP, nodeKey)
		return false
	}
	g.lastForceSync = time.Now()
	g.mu.Unlock()

	syncOK := g.forceSync()

	g.mu.RLock()
	meta, allowed = g.nodes[nodeKey]
	g.mu.RUnlock()
	if allowed {
		log.Printf("[ADMIT] ALLOW (after force sync) friend=%s device=%s user=%s ip=%s key=%s", meta.Friend, meta.Device, meta.User, sourceIP, nodeKey)
		return true
	}
	if !syncOK {
		log.Printf("[ADMIT] DENY (sync incomplete, skipping neg-cache) ip=%s key=%s", sourceIP, nodeKey)
		return false
	}
	g.mu.Lock()
	g.negCache[nodeKey] = time.Now().Add(time.Duration(g.currentPollIntervalLocked()) * time.Second)
	g.mu.Unlock()
	log.Printf("[ADMIT] DENY (unknown node after sync) ip=%s key=%s", sourceIP, nodeKey)
	return false
}

// currentPollIntervalLocked requires g.mu to be held (read or write).
func (g *Guard) currentPollIntervalLocked() int {
	if g.cfg.PollIntervalSec <= 0 {
		return 600
	}
	return g.cfg.PollIntervalSec
}

// forceSync runs one SyncAll synchronously with a 4.5s wait cap (derper's own
// /admit timeout is 5s; we leave headroom). If the API takes slightly longer
// than 4.5s, the goroutine still finishes up to perFriendTimeout (8s) to warm
// the table for the next retry, while returning false so Verify skips negCache.
func (g *Guard) forceSync() bool {
	done := make(chan bool, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), perFriendTimeout)
		defer cancel()
		done <- g.SyncAll(ctx)
	}()
	select {
	case ok := <-done:
		return ok
	case <-time.After(4500 * time.Millisecond):
		return false
	}
}

// pollLoop runs the periodic sync loop (interval is hot-reloadable via SIGHUP)
// and defers the next scheduled poll whenever an on-demand SyncAll already ran.
func (g *Guard) pollLoop(ctx context.Context) {
	for {
		g.mu.RLock()
		interval := time.Duration(g.currentPollIntervalLocked()) * time.Second
		lastSync := g.lastSync
		g.mu.RUnlock()

		wait := interval
		if !lastSync.IsZero() {
			if rem := interval - time.Since(lastSync); rem < wait {
				wait = rem
			}
		}
		if wait < time.Second {
			wait = time.Second
		}

		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}

		g.mu.RLock()
		interval = time.Duration(g.currentPollIntervalLocked()) * time.Second
		recent := !g.lastSync.IsZero() && time.Since(g.lastSync) < interval-500*time.Millisecond
		g.mu.RUnlock()
		if recent {
			continue
		}

		g.SyncAll(ctx)
	}
}

// StatusSnapshot builds the JSON snapshot served by /status.
func (g *Guard) StatusSnapshot(certFP string, derperPID int) map[string]any {
	g.mu.RLock()
	defer g.mu.RUnlock()
	friends := make([]map[string]any, 0, len(g.cfg.Friends))
	for _, f := range g.cfg.Friends {
		friends = append(friends, map[string]any{
			"name":  f.Name,
			"nodes": len(g.byFriend[f.Name]),
		})
	}
	return map[string]any{
		"status":          "ok",
		"uptime_sec":      int(time.Since(g.startedAt).Seconds()),
		"nodes_total":     len(g.nodes),
		"static_nodes":    len(g.cfg.StaticNodes),
		"friends":         friends,
		"negative_cached": len(g.negCache),
		"last_force_sync": g.lastForceSync.UTC().Format(time.RFC3339),
		"cert_sha256_raw": certFP,
		"derper_pid":      derperPID,
	}
}

// ============================================================================
// Node cache snapshot (disk persistence)
// ============================================================================

type nodeCacheFile struct {
	SavedAt  time.Time                      `json:"saved_at"`
	ByFriend map[string]map[string]NodeMeta `json:"by_friend"`
}

// writeCacheBytes writes pre-marshaled JSON to path+".tmp" first, then os.Rename — atomic.
func writeCacheBytes(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadCache loads the disk snapshot at startup so a Tailscale API outage right
// after a restart cannot leave us with an empty table. Friends no longer
// present in the current config are pruned immediately.
func (g *Guard) LoadCache(path string) {
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[GUARD] no node cache snapshot found, starting cold (%v)", err)
		return
	}
	var c nodeCacheFile
	if err := json.Unmarshal(data, &c); err != nil {
		log.Printf("[GUARD] WARN corrupt node cache snapshot, ignoring: %v", err)
		return
	}
	if c.ByFriend == nil {
		c.ByFriend = map[string]map[string]NodeMeta{}
	}

	g.mu.Lock()
	keep := make(map[string]bool, len(g.cfg.Friends))
	for _, f := range g.cfg.Friends {
		keep[f.Name] = true
	}
	filtered := make(map[string]map[string]NodeMeta, len(c.ByFriend))
	pruned := 0
	total := 0
	for name, m := range c.ByFriend {
		if !keep[name] {
			pruned++
			continue
		}
		filtered[name] = m
		total += len(m)
	}
	g.byFriend = filtered
	g.mu.Unlock()

	log.Printf("[GUARD] loaded node cache snapshot: %d friends / %d nodes (saved at %s)",
		len(filtered), total, c.SavedAt.Local().Format(time.RFC3339))
	if pruned > 0 {
		log.Printf("[GUARD] pruned %d removed friend(s) from cached snapshot", pruned)
	}
	g.rebuildAndPersist(pruned > 0)
}
