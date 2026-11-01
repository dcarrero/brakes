# Seeded by brakes (agent-guardrails): a Claude Code container with
# default-deny egress (https://code.claude.com/docs/en/devcontainer). The
# project owns this file once it exists: add the stack's toolchain below, and
# every host it downloads from at run time to init-firewall.sh.
FROM {{image}}

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl dnsutils git iproute2 ipset iptables jq sudo \
 && rm -rf /var/lib/apt/lists/*

# Claude Code at a pinned version; devcontainer.json turns the auto-updater off.
RUN npm install -g {{claude_code}} && npm cache clean --force

# The firewall runs as root at every start; `node` may run that script and
# nothing else through sudo.
COPY init-firewall.sh /usr/local/bin/init-firewall.sh
RUN chmod 0755 /usr/local/bin/init-firewall.sh \
 && printf 'node ALL=(root) NOPASSWD: /usr/local/bin/init-firewall.sh\n' > /etc/sudoers.d/node-firewall \
 && chmod 0440 /etc/sudoers.d/node-firewall \
 && mkdir -p /home/node/.claude \
 && chown node:node /home/node/.claude

USER node
