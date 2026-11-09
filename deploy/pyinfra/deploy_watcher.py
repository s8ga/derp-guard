# One-shot deploy of the upstream release watcher on watcher_servers:
#   watch-tailscale.sh + /etc/default/watch-tailscale (contains the PAT, 0600)
#   + systemd timer (every 5 minutes)
from pyinfra import host
from pyinfra.operations import files, systemd

watcher = host.data.watcher

files.put(
    name="Deploy watch-tailscale.sh",
    src="deploy/gcp-watcher/watch-tailscale.sh",
    dest="/usr/local/sbin/watch-tailscale.sh",
    mode="0755",
    _sudo=True,
)

files.template(
    name="Render /etc/default/watch-tailscale (contains GH_PAT, 0600)",
    src="deploy/pyinfra/templates/watch-tailscale.default.j2",
    dest="/etc/default/watch-tailscale",
    mode="0600",
    gh_pat=watcher["gh_pat"],
    target_repo=watcher["target_repo"],
    _sudo=True,
)

files.put(
    name="Deploy watch-tailscale.service",
    src="deploy/gcp-watcher/watch-tailscale.service",
    dest="/etc/systemd/system/watch-tailscale.service",
    _sudo=True,
)

files.put(
    name="Deploy watch-tailscale.timer",
    src="deploy/gcp-watcher/watch-tailscale.timer",
    dest="/etc/systemd/system/watch-tailscale.timer",
    _sudo=True,
)

systemd.service(
    name="Enable watch-tailscale.timer",
    service="watch-tailscale.timer",
    running=True,
    enabled=True,
    daemon_reload=True,
    _sudo=True,
)
