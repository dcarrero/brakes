#!/bin/bash
# Seeded by brakes (agent-guardrails): default-deny egress for the dev
# container, run as root at every start (devcontainer.json, postStartCommand).
# Outbound traffic is allowed to loopback, DNS, replies to allowed connections
# and the addresses the hosts below resolve to now; everything else is
# rejected. A host whose addresses change after the start is unreachable until
# the next start. IPv6 egress is closed. The project owns this file once it
# exists: a host added here is a host every agent session can reach.
set -euo pipefail

ALLOWED_HOSTS="
github.com
api.github.com
api.anthropic.com
claude.ai
platform.claude.com
proxy.golang.org
sum.golang.org
"

iptables -P OUTPUT ACCEPT
iptables -F OUTPUT
ipset destroy agent-egress 2>/dev/null || true
ipset create agent-egress hash:ip

for host in $ALLOWED_HOSTS; do
  addresses=$(dig +short A "$host" | grep -E '^[0-9]+(\.[0-9]+){3}$' || true)
  if [ -z "$addresses" ]; then
    echo "init-firewall: cannot resolve $host" >&2
    exit 1
  fi
  for address in $addresses; do
    ipset add -exist agent-egress "$address"
  done
done

iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m set --match-set agent-egress dst -j ACCEPT
iptables -A OUTPUT -j REJECT --reject-with icmp-admin-prohibited
iptables -P OUTPUT DROP

ip6tables -P OUTPUT ACCEPT
ip6tables -F OUTPUT
ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -A OUTPUT -j REJECT
ip6tables -P OUTPUT DROP

if curl --silent --connect-timeout 5 --output /dev/null https://example.com; then
  echo "init-firewall: https://example.com is reachable; egress is not closed" >&2
  exit 1
fi
if ! curl --silent --connect-timeout 5 --output /dev/null https://api.github.com/zen; then
  echo "init-firewall: https://api.github.com is unreachable" >&2
  exit 1
fi
echo "init-firewall: egress limited to the allowed hosts"
