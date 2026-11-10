#!/bin/sh
set -e

if ! getent group derp-guard >/dev/null 2>&1; then
    groupadd --system derp-guard
fi

if ! getent passwd derp-guard >/dev/null 2>&1; then
    useradd --system --gid derp-guard \
        --home-dir /var/lib/derp-guard --no-create-home \
        --shell /usr/sbin/nologin \
        --comment "derp-guard daemon" derp-guard
fi

install -d -m 0750 -o root -g derp-guard /etc/derp-guard
if [ -f /etc/derp-guard/config.toml ]; then
    chown root:derp-guard /etc/derp-guard/config.toml
    chmod 0640 /etc/derp-guard/config.toml
fi

install -d -m 0700 -o derp-guard -g derp-guard /var/lib/derp-guard
chown -R derp-guard:derp-guard /var/lib/derp-guard
