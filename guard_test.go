package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func jsonResp(status int, v any) *http.Response {
	b, _ := json.Marshal(v)
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(b)),
	}
}

func TestGuardLoadCachePrunesRemovedFriends(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "nodes_cache.json")

	raw := nodeCacheFile{
		SavedAt: time.Now().UTC(),
		ByFriend: map[string]map[string]NodeMeta{
			"alice": {"nodekey:aaaa": {Friend: "alice", Device: "alice-pc", User: "alice@example.com"}},
			"bob":   {"nodekey:bbbb": {Friend: "bob", Device: "bob-pc", User: "bob@example.com"}},
		},
	}
	data, _ := json.Marshal(&raw)
	if err := os.WriteFile(cachePath, data, 0600); err != nil {
		t.Fatal(err)
	}

	g := newGuard(GuardConfig{
		CacheFile: cachePath,
		Friends:   []Friend{{Name: "alice", ClientID: "id", ClientSecret: "sec"}},
	})
	g.LoadCache(cachePath)

	if !g.Verify("nodekey:aaaa", "127.0.0.1") {
		t.Fatal("expected alice's cached node to be admitted")
	}
	if _, ok := g.nodes["nodekey:bbbb"]; ok {
		t.Fatal("expected removed friend bob's cached node to be pruned on LoadCache")
	}
}

func TestGuardVerifySkipsNegCacheOnTransientError(t *testing.T) {
	var failDevices atomic.Bool
	failDevices.Store(true)

	g := newGuard(GuardConfig{
		PollIntervalSec: 600,
		MissCooldownSec: 1,
		Friends:         []Friend{{Name: "me", ClientID: "id", ClientSecret: "sec"}},
	})
	g.client = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch r.URL.String() {
			case tailscaleTokenURL:
				return jsonResp(http.StatusOK, tokenResp{AccessToken: "tok", ExpiresIn: 3600}), nil
			case tailscaleDevicesURL:
				if failDevices.Load() {
					return jsonResp(http.StatusBadGateway, map[string]any{}), nil
				}
				return jsonResp(http.StatusOK, devicesResp{
					Devices: []deviceJSON{
						{NodeKey: "nodekey:newdev", Hostname: "laptop", User: "u@example.com", Authorized: true},
					},
				}), nil
			default:
				return jsonResp(http.StatusNotFound, nil), nil
			}
		}),
	}

	if g.Verify("nodekey:newdev", "127.0.0.1") {
		t.Fatal("expected deny on transient API failure")
	}
	if _, neg := g.negCache["nodekey:newdev"]; neg {
		t.Fatal("transient sync failure must not poison negCache")
	}

	failDevices.Store(false)
	g.lastForceSync = g.lastForceSync.Add(-5 * time.Second)
	if !g.Verify("nodekey:newdev", "127.0.0.1") {
		t.Fatal("expected new device to be admitted once API recovers")
	}

	g.lastForceSync = g.lastForceSync.Add(-5 * time.Second)
	if g.Verify("nodekey:stranger", "127.0.0.1") {
		t.Fatal("expected unknown node to be denied")
	}
	if _, neg := g.negCache["nodekey:stranger"]; !neg {
		t.Fatal("expected unknown node after clean sync to be cached in negCache")
	}
}

func TestGuardNoRedundantDiskWriteAndConcurrentReload(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "nodes_cache.json")
	cfg := GuardConfig{
		CacheFile: cachePath,
		Friends:   []Friend{{Name: "me", ClientID: "id", ClientSecret: "sec"}},
	}
	g := newGuard(cfg)
	g.client = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch r.URL.String() {
			case tailscaleTokenURL:
				return jsonResp(http.StatusOK, tokenResp{AccessToken: "tok", ExpiresIn: 3600}), nil
			case tailscaleDevicesURL:
				return jsonResp(http.StatusOK, devicesResp{
					Devices: []deviceJSON{
						{NodeKey: "nodekey:1111", Hostname: "box", User: "u@example.com", Authorized: true},
						{NodeKey: "nodekey:ext", Hostname: "ext", User: "ext@example.com", Authorized: true, IsExternal: true},
					},
				}), nil
			default:
				return jsonResp(http.StatusNotFound, nil), nil
			}
		}),
	}

	if !g.SyncAll(context.Background()) {
		t.Fatal("expected initial SyncAll to succeed")
	}
	st1, err := os.Stat(cachePath)
	if err != nil {
		t.Fatalf("expected cache file to be written: %v", err)
	}

	time.Sleep(15 * time.Millisecond)
	if !g.SyncAll(context.Background()) {
		t.Fatal("expected second SyncAll to succeed")
	}
	st2, err := os.Stat(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Fatalf("expected unchanged SyncAll not to rewrite cache file (%v vs %v)", st1.ModTime(), st2.ModTime())
	}

	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			g.SyncAll(context.Background())
		}()
		go func(i int) {
			defer wg.Done()
			nc := cfg
			if i%2 == 0 {
				nc.Friends = append([]Friend{}, cfg.Friends...)
				nc.Friends = append(nc.Friends, Friend{Name: "temp", ClientID: "id", ClientSecret: "sec"})
			}
			g.UpdateConfig(nc)
		}(i)
	}
	wg.Wait()
}
