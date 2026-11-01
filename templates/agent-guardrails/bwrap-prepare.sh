# bwrap-prepare.sh (brakes agent-guardrails; #1079, #971):
# CLAUDE_CODE_SUBPROCESS_ENV_SCRUB needs bubblewrap, which the pinned action
# installed only for non-write users, and Ubuntu 24.04 restricts the unprivileged
# user namespaces bubblewrap uses. An AppArmor profile lets /usr/bin/bwrap alone
# create them, so kernel.apparmor_restrict_unprivileged_userns stays on for every
# other program, and what bwrap runs gets neither capabilities nor user namespaces.
# Then bubblewrap must work for MODEL_USER and nothing inside it may nest a user
# namespace, or the model never starts.
set -euo pipefail

: "${MODEL_USER:?MODEL_USER is the user the model runs as}"
for attempt in 1 2 3; do
  sudo apt-get update -qq && sudo apt-get install -y --no-install-recommends bubblewrap socat && break
  [ "$attempt" = 3 ] && exit 1
  sleep 5
done
if [ -f /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
  # Modelled on AppArmor's bwrap-userns-restrict (apparmor-4.1,
  # profiles/apparmor/profiles/extras/bwrap-userns-restrict, read 2026-10-30): bwrap
  # may create user namespaces; whatever it runs is stacked against
  # agent-unpriv-bwrap, which denies capabilities and further user namespaces.
  sudo tee /etc/apparmor.d/agent-bwrap >/dev/null <<'PROFILE'
abi <abi/4.0>,

include <tunables/global>

profile agent-bwrap /usr/bin/bwrap flags=(attach_disconnected,mediate_deleted) {
  allow capability,
  allow file rwlkm /{**,},
  allow network,
  allow unix,
  allow ptrace,
  allow signal,
  allow mqueue,
  allow io_uring,
  allow userns,
  allow mount,
  allow umount,
  allow pivot_root,
  allow dbus,
  allow pix /** -> &agent-bwrap//&agent-unpriv-bwrap,
}

profile agent-unpriv-bwrap flags=(attach_disconnected,mediate_deleted) {
  allow file rwlkm /{**,},
  allow network,
  allow unix,
  allow ptrace,
  allow signal,
  allow mqueue,
  allow io_uring,
  allow mount,
  allow umount,
  allow pivot_root,
  allow dbus,
  allow pix /** -> &agent-unpriv-bwrap,
  audit deny capability,
  audit deny userns,
}
PROFILE
  sudo apparmor_parser -r /etc/apparmor.d/agent-bwrap
fi
if ! sudo -u "$MODEL_USER" -H -- bwrap --unshare-user --ro-bind / / true; then
  echo "::error::bubblewrap cannot create a user namespace for $MODEL_USER; the scrub would refuse to start"
  exit 1
fi
if sudo -u "$MODEL_USER" -H -- bwrap --unshare-user --ro-bind / / unshare -U true 2>/dev/null; then
  echo "::error::a program inside bubblewrap could create a user namespace; the profile is not in force"
  exit 1
fi
echo "bubblewrap: user namespaces for $MODEL_USER through the agent-bwrap profile; none inside"
