#!/bin/sh
# Postinstall for orchestrator-watcher: create the unprivileged user and its
# adoption directory. The service is NOT enabled or started here — the adoption
# file must exist first, and starting an agent that cannot authenticate would
# only crash-loop.
set -e

if ! getent group orchestrator-watcher >/dev/null 2>&1; then
    groupadd --system orchestrator-watcher
fi
if ! getent passwd orchestrator-watcher >/dev/null 2>&1; then
    useradd --system --gid orchestrator-watcher --shell /usr/sbin/nologin \
        --home-dir /nonexistent --no-create-home orchestrator-watcher
fi

mkdir -p /etc/orchestrator-watcher
chown orchestrator-watcher:orchestrator-watcher /etc/orchestrator-watcher
chmod 0750 /etc/orchestrator-watcher

systemctl daemon-reload 2>/dev/null || true

# If the full agent's adoption file exists, offer it as the seed: copying it is
# an explicit operator action (documented), never automatic — the file is
# root-owned 0600 and holds the node's credential.
if [ -f /etc/orchestrator/node-adoption.txt ] && [ ! -f /etc/orchestrator-watcher/node-adoption.txt ]; then
    echo "orchestrator-watcher: seed the adoption file with:" >&2
    echo "  install -o orchestrator-watcher -g orchestrator-watcher -m 0600 \\" >&2
    echo "    /etc/orchestrator/node-adoption.txt /etc/orchestrator-watcher/node-adoption.txt" >&2
    echo "then: systemctl enable --now orchestrator-watcher" >&2
fi
