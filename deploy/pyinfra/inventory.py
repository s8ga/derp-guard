# pyinfra inventory example
#
# Usage:
#   pyinfra deploy/pyinfra/inventory.py deploy/pyinfra/deploy_derp.py
#   pyinfra deploy/pyinfra/inventory.py deploy/pyinfra/deploy_watcher.py
#
# Each key in host_data is a hostname; the value holds that host's variables
# (accessed as host.data.* in the deploy scripts).

# Hosts running the DERP server (tailscale-derper-oauth package)
derp_servers = [
    "derp1.example.com",
    # "derp2.example.com",
]

# Spare hosts (e.g. a lightweight GCP VM) running the upstream release watcher timer
watcher_servers = [
    # "watch.example.com",
]

host_data = {
    "derp1.example.com": {
        # ---- APT repo ----
        # Without GPG signing use trusted=yes; once signing is enabled, drop
        # pubkey.gpg into this directory and set apt_pubkey_src.
        "apt_repo_url": "https://s8ga.github.io/derp-guard/ ./",
        "apt_trusted": True,
        # "apt_pubkey_src": "deploy/pyinfra/pubkey.gpg",

        # ---- /etc/derper/config.toml rendering vars (see templates/config.toml.j2) ----
        "derp": {
            "hostname": "derp1.example.com",
            "listen_addr": ":443",
            "http_port": -1,
            "stun_port": 3478,
            "home": "blank",
            "cert_mode": "derper_letsencrypt",
            "cert_file": "",
            "key_file": "",
            "ipv4": "",
        },
        "guard": {
            "poll_interval_sec": 300,
            "miss_cooldown_sec": 60,
            "revoke_on_auth_err": True,
            "status_listen": "127.0.0.1:8001",
            "static_nodes": {
                # "nodekey:0123...def": "emergency-laptop",
            },
            "friends": [
                {"name": "Me", "client_id": "k111111CNTRL",
                 "client_secret": "tskey-client-k111111CNTRL-xxxxxx"},
                {"name": "Alice", "client_id": "k222222CNTRL",
                 "client_secret": "tskey-client-k222222CNTRL-yyyyyy"},
            ],
        },

        # ---- upstream watcher (deploy_watcher.py) ----
        "watcher": {
            "gh_pat": "github_pat_xxx",
            "target_repo": "s8ga/derp-guard",
        },
    },
}
