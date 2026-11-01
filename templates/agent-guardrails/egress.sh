# egress.sh (brakes agent-guardrails; SPEC-agent-guardrails.md, "Egress
# allowlist", as built #971). The model runs as EGRESS_USER, a user without sudo,
# created here. Only that user's outbound traffic is closed, IPv4 and IPv6: it keeps
# loopback (its credential proxy listens there) but not DNS on it, replies to its
# open connections, IPv6 router and neighbour discovery on the link, and the
# addresses of EGRESS_HOSTS, which go to /etc/hosts because the user has no DNS at
# all: no packet to port 53, no systemd-resolved varlink socket, no resolve1 on
# D-Bus. The runner's own traffic (artifacts, logs, the VM agent) is untouched.
# Then the limit is proved as that user; any failure fails the job before the model
# starts. With EGRESS_MODE=check only the proof runs again, and EGRESS_PROBE_URL,
# when set, must answer (the proxy, right before the model). One rule per address:
# neither runner image has ipset.
set -euo pipefail

fail() {
  echo "::error::egress: $*"
  exit 1
}
: "${EGRESS_USER:?EGRESS_USER names the user the model runs as}"
user=$EGRESS_USER
blocked="${EGRESS_BLOCKED_URL:-https://example.com}"
as_user() { sudo -u "$user" -H -- "$@"; }

prove() {
  if as_user curl --silent --max-time 10 --output /dev/null "$blocked"; then
    fail "$blocked is reachable as $user; its outbound traffic is not closed"
  fi
  if as_user timeout 10 getent hosts example.com >/dev/null 2>&1; then
    fail "$user resolves names through the system resolver; DNS is a channel out"
  fi
  if command -v resolvectl >/dev/null && as_user timeout 10 resolvectl query example.com >/dev/null 2>&1; then
    fail "$user resolves names through systemd-resolved; DNS is a channel out"
  fi
  if as_user timeout 10 dig +time=2 +tries=1 example.com >/dev/null 2>&1; then
    fail "$user queries the resolver directly; DNS is a channel out"
  fi
  if as_user timeout 10 bash -c 'echo probe >/dev/udp/192.0.2.1/9' 2>/dev/null; then
    fail "$user can send UDP out; its outbound traffic is not closed"
  fi
  if as_user sudo -n true >/dev/null 2>&1 || as_user sudo -n -l >/dev/null 2>&1; then
    fail "$user can use sudo; it could lift the limit"
  fi
  groups=$(id -Gn "$user")
  [ "$groups" = "$user" ] || fail "$user is in groups $groups; it must be in its own group only"
  if [ -S /var/run/docker.sock ] && as_user test -w /var/run/docker.sock; then
    fail "$user can write the Docker socket; it could run as root"
  fi
  answered=""
  if [ -n "${EGRESS_PROBE_URL:-}" ]; then
    code=$(as_user curl --silent --max-time 20 --output /dev/null --write-out '%{http_code}' "$EGRESS_PROBE_URL" || true)
    if [ -z "$code" ] || [ "$code" = "000" ]; then
      fail "$EGRESS_PROBE_URL is unreachable as $user"
    fi
    answered=", $EGRESS_PROBE_URL answered $code"
  fi
  echo "egress: $user confined; $blocked refused, DNS refused, UDP refused$answered; sudo refused; groups $groups"
}

for tool in sudo iptables ip6tables dig curl useradd setfacl timeout getent; do
  command -v "$tool" >/dev/null || fail "$tool is not on this runner; the model does not start unconfined"
done

if [ "${EGRESS_MODE:-limit}" = "check" ]; then
  prove
  exit 0
fi

if ! id "$user" >/dev/null 2>&1; then
  sudo useradd --create-home --shell /bin/bash "$user"
fi
# The home is 0755: Codex's proxy, which runs as the runner, writes its server
# file there; the model's own files stay its own.
sudo chmod 755 "/home/$user"

# No name resolution for the user except the hosts below, written to /etc/hosts.
allowed=""
for host in ${EGRESS_HOSTS:-}; do
  addresses=$(dig +short A "$host" | grep -E '^[0-9]+(\.[0-9]+){3}$' || true)
  [ -n "$addresses" ] || fail "cannot resolve $host"
  while IFS= read -r address; do
    printf '%s %s\n' "$address" "$host" | sudo tee -a /etc/hosts >/dev/null
  done <<<"$addresses"
  allowed="$allowed$addresses"$'\n'
  echo "egress: $host -> $(xargs <<<"$addresses")"
done
if [ -S /run/systemd/resolve/io.systemd.Resolve ]; then
  sudo setfacl -m "u:$user:---" /run/systemd/resolve/io.systemd.Resolve
fi
if [ -d /etc/dbus-1/system.d ]; then
  printf '%s\n' '<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">' \
    "<busconfig><policy user=\"$user\"><deny send_destination=\"org.freedesktop.resolve1\"/></policy></busconfig>" |
    sudo tee /etc/dbus-1/system.d/zz-agent-egress.conf >/dev/null
  sudo systemctl reload dbus 2>/dev/null || sudo dbus-send --system --type=method_call --dest=org.freedesktop.DBus / org.freedesktop.DBus.ReloadConfig
fi

chain=AGENT-EGRESS
for ipt in iptables ip6tables; do
  sudo "$ipt" -N "$chain"
  for proto in udp tcp; do
    sudo "$ipt" -A "$chain" -o lo -p "$proto" --dport 53 -j REJECT
  done
  sudo "$ipt" -A "$chain" -o lo -j ACCEPT
  sudo "$ipt" -A "$chain" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
done
for type in 133 134 135 136; do
  for scope in fe80::/10 ff02::/16; do
    sudo ip6tables -A "$chain" -d "$scope" -p ipv6-icmp --icmpv6-type "$type" -m hl --hl-eq 255 -j ACCEPT
  done
done
while IFS= read -r address; do
  [ -z "$address" ] || sudo iptables -A "$chain" -d "$address" -j ACCEPT
done < <(printf '%s' "$allowed" | sort -u)
sudo iptables -A "$chain" -j LOG --log-prefix "egress-reject: " --log-level 4
sudo ip6tables -A "$chain" -j LOG --log-prefix "egress-reject: " --log-level 4
sudo iptables -A "$chain" -j REJECT --reject-with icmp-admin-prohibited
sudo ip6tables -A "$chain" -j REJECT --reject-with icmp6-adm-prohibited
uid=$(id -u "$user")
sudo iptables -I OUTPUT 1 -m owner --uid-owner "$uid" -j "$chain"
sudo ip6tables -I OUTPUT 1 -m owner --uid-owner "$uid" -j "$chain"

prove
