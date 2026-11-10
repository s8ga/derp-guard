# derp-guard

The unmodified upstream [derper](https://github.com/tailscale/tailscale/tree/main/cmd/derper) plus a cross-tailnet admission controller, packaged as a single deb (`derp-guard`).

The problem it solves: you and your friends each have your own Tailscale tailnet and don't want to merge them, but want to share one self-hosted DERP server. Each friend provides a read-only OAuth client (`devices:core:read`); derp-guard periodically pulls every tailnet's device list and only admits devices that are authorized and not shared in externally. derper itself is untouched — CI builds it from the upstream tag — and admission goes through its existing `--verify-client-url` hook, with `--verify-client-url-fail-open=false` passed explicitly: if the admission service is unreachable, connections are refused, not allowed.

## How it works

One systemd unit (`derp-guard.service`) starts `/usr/bin/derp-guard`, which reads a single config file (`/etc/derp-guard/config.toml`):

1. Loads the on-disk node snapshot (`cache_file`) first, so a Tailscale API outage right after a restart can't start it with an empty table;
2. Fetches every friend's device list concurrently (tokens cached and reused, 8s per-request timeout), keeps only `authorized && !isExternal` devices, merges the static allowlist into an admission table, and writes it back to disk atomically;
3. Starts `POST /admit` on a random `127.0.0.1` port, then spawns `/usr/libexec/derper` as a child process (stdout/stderr passed through).

Every DERP client connection triggers one `/admit` call, checked in order:

1. In the allow table → admit (refreshed fully every `poll_interval_sec`);
2. In the negative cache (recently denied nodekeys) → instant deny, zero API calls, so scanners can't burn your quota;
3. Miss on both, and the last forced sync is older than `miss_cooldown_sec` → sync once and re-check (covers brand-new devices), otherwise deny and remember in the negative cache.

Errors are isolated per friend: revoked credentials (token 400/401, or device-list 401 that still fails after a token refresh) clear that friend's devices immediately when `revoke_on_auth_err = true` — revoking a client takes effect right away; transient errors (timeouts, DNS, 429/5xx) keep the friend's last good snapshot, so a bad API day never locks out online users.

Operational behavior:

- `systemctl reload derp-guard` sends SIGHUP: friend/allowlist changes hot-reload the guard config without dropping connections; `[derper]` section or certificate changes gracefully restart the child process.
- If derper crashes it is restarted with exponential backoff (1s→2s→4s→8s→16s→30s); the counter resets after 60s of stable uptime.
- In `custom_selfsigned` / `external_letsencrypt` modes the cert file hash is checked every `cert_check_interval_sec`; on change derper restarts only if validation passes (key pair matches, not expired, hostname matches). A half-written cert (external tool mid-renewal) just logs a warning.

## Install

Shared APT repo (hosted at [s8ga/repo](https://github.com/s8ga/repo); a scheduled collector picks up new releases automatically):

```bash
echo "deb [trusted=yes] https://s8ga.github.io/repo/deb/ ./" \
  | sudo tee /etc/apt/sources.list.d/s8ga.list
sudo apt update && sudo apt install derp-guard
```

Unsigned on purpose: everything is served over authenticated HTTPS from GitHub Pages by the same account that builds the packages, so signatures add no real protection here. Alternatively grab the deb directly from [Releases](https://github.com/s8ga/derp-guard/releases).

What gets installed: `/usr/bin/derp-guard` (this repo), `/usr/libexec/derper` (official binary), `/etc/derp-guard/config.toml` (noreplace, survives upgrades, 0600), and `derp-guard.service`.

## Friend side

1. Open <https://login.tailscale.com/admin/settings/oauth>, Generate OAuth client, scope only **Devices → Core → Read**;
2. Send the client ID and secret to the server admin (the secret is shown once).

The admin adds it to the config and hot-reloads:

```toml
[[guard.friends]]
name          = "Alice"
client_id     = "k222222CNTRL"
client_secret = "tskey-client-k222222CNTRL-yyyyyy"
```

```bash
sudo systemctl reload derp-guard
```

Then each friend adds the derpMap (next section) to their own ACL.

## Config and cert modes

All fields are documented in [packaging/config.example.toml](packaging/config.example.toml). `cert_mode`, pick one of five:

**reverse_proxy** — Caddy/Nginx in front terminates TLS. derper serves plain HTTP:

```toml
cert_mode   = "reverse_proxy"
listen_addr = "127.0.0.1:3340"  # not 443: port 443 makes derper force TLS and startup fails
```

**derper_selfsigned** — no domain, public IP only; derper generates a self-signed cert on first start:

```toml
cert_mode = "derper_selfsigned"
hostname  = "203.0.113.10"
```

**custom_selfsigned** — a self-signed cert you manage yourself (a CA chain gets rejected by Tailscale clients):

```toml
cert_mode = "custom_selfsigned"
cert_file = "/root/derp.crt"
key_file  = "/root/derp.key"
```

**derper_letsencrypt** — derper's built-in ACME; needs a public domain and ports 80/443:

```toml
cert_mode   = "derper_letsencrypt"
hostname    = "derp.example.com"
listen_addr = ":443"
http_port   = 80
```

**external_letsencrypt** — certbot/acme.sh owns the cert; renewals hot-reload automatically:

```toml
cert_mode = "external_letsencrypt"
hostname  = "derp.example.com"
cert_file = "/etc/letsencrypt/live/derp.example.com/fullchain.pem"
key_file  = "/etc/letsencrypt/live/derp.example.com/privkey.pem"
```

## derpMap

Friends paste the derpMap into their own ACL (<https://login.tailscale.com/admin/acls>, the `"derpMap"` field). The admin runs:

```bash
derp-guard derpmap -config /etc/derp-guard/config.toml
```

Self-signed modes get `CertName: "sha256-raw:..."` filled in automatically (the fingerprint also appears in the startup log and in `GET /status` as `cert_sha256_raw`); with `ipv4` configured it emits `"IPv4"` plus `"IPv6": "none"`.

## Day-to-day ops

```bash
curl -s http://127.0.0.1:8001/status | jq   # node counts, friends, neg cache, derper PID, cert fingerprint
journalctl -u derp-guard -f | grep ADMIT        # live admission log
```

Emergency static allowlist (bypasses the API when everything is down):

```toml
[guard.static_nodes]
"nodekey:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" = "emergency-laptop"
```

## Deployment and upstream tracking

[deploy/pyinfra](deploy/pyinfra): hosts and variables live in [inventory.py](deploy/pyinfra/inventory.py); `pyinfra inventory.py deploy_derp.py` configures the APT repo, installs/upgrades the package, renders the config, and couples systemd (package update → restart, config-only change → reload, i.e. SIGHUP).

Upstream tracking: a push to main or an `upstream_release` dispatch makes CI build dual-arch debs from the latest stable Tailscale tag and publish them as a Release (version = `upstream version - repo commit count`; already-published versions are skipped). The shared APT pool at [s8ga/repo](https://github.com/s8ga/repo) collects new releases on a daily schedule. [deploy/gcp-watcher](deploy/gcp-watcher) runs on any always-on box, polls the upstream release every 5 minutes using ETag/304 at zero quota cost, and dispatches on new tags (needs a PAT in `/etc/default/watch-tailscale`).

## Building

Go 1.22+, sole third-party dependency BurntSushi/toml, static build with `CGO_ENABLED=0`:

```bash
CGO_ENABLED=0 go vet ./...
CGO_ENABLED=0 go build -o build/derp-guard .
git clone --depth 1 --branch v1.104.5 https://github.com/tailscale/tailscale.git
(cd tailscale && CGO_ENABLED=0 go build -ldflags="-s -w" -o ../build/derper ./cmd/derper)
```

MIT, see [LICENSE](LICENSE). The derper binary remains under the upstream BSD-3-Clause license.
