# Deploy/update tailscale-derper-oauth on derp_servers:
#   1. configure the APT repo (optional signed-by; trusted=yes when unsigned)
#   2. install/upgrade the package
#   3. render /etc/derp-guard/config.toml (0600)
#   4. systemd coupling: package update -> restart; config-only change ->
#      reload (SIGHUP, lossless hot reload)
from pyinfra import host
from pyinfra.operations import apt, files, systemd

apt_repo_url = host.data.apt_repo_url
apt_trusted = host.data.get("apt_trusted", True)
apt_pubkey_src = host.data.get("apt_pubkey_src")

# ---- 1. APT repo ----
if apt_pubkey_src:
    files.put(
        name="Install APT repo pubkey",
        src=apt_pubkey_src,
        dest="/usr/share/keyrings/tailscale-derper-oauth.gpg",
        mode="0644",
        _sudo=True,
    )
    source_line = (
        f"deb [signed-by=/usr/share/keyrings/tailscale-derper-oauth.gpg] {apt_repo_url}"
    )
else:
    source_line = f"deb [trusted=yes] {apt_repo_url}"

files.line(
    name="Configure APT repo /etc/apt/sources.list.d/tailscale-derper-oauth.list",
    path="/etc/apt/sources.list.d/tailscale-derper-oauth.list",
    line=source_line,
    present=True,
    _sudo=True,
)

# ---- 2. install/upgrade ----
pkg = apt.packages(
    name="Install/upgrade derp-guard",
    packages=["derp-guard"],
    update=True,
    _sudo=True,
)

# ---- 3. render config ----
files.directory(
    name="Ensure /etc/derp-guard",
    path="/etc/derp-guard",
    user="root",
    group="derp-guard",
    mode="0750",
    _sudo=True,
)

cfg = files.template(
    name="Render /etc/derp-guard/config.toml",
    src="deploy/pyinfra/templates/config.toml.j2",
    dest="/etc/derp-guard/config.toml",
    user="root",
    group="derp-guard",
    mode="0640",
    derp=host.data.derp,
    guard=host.data.guard,
    _sudo=True,
)

# ---- 4. systemd coupling ----
# A package update (new binaries) always requires a restart; a config-only
# change uses reload to trigger the SIGHUP lossless hot reload.
systemd.service(
    name="Enable and keep derp-guard.service running",
    service="derp-guard",
    running=True,
    enabled=True,
    daemon_reload=pkg.changed,
    restarted=pkg.changed,
    reloaded=(not pkg.changed and cfg.changed),
    _sudo=True,
)
