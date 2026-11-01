# model-copy.sh (brakes agent-guardrails; #971): the model works on a copy
# of the prepared checkout that MODEL_USER owns, with its context (the issue or
# the pull request's description) beside it, because /home/runner is 0750 and the
# model reads nothing of the runner's. MODEL_GIT_NAME and MODEL_GIT_EMAIL, when set,
# are the identity it commits with.
set -euo pipefail

: "${MODEL_USER:?MODEL_USER is the user the model runs as}"
home="/home/$MODEL_USER"
sudo rm -rf "$home/work" "$home/context"
sudo install -d -o "$MODEL_USER" -g "$MODEL_USER" -m 755 "$home/work" "$home/context"
sudo cp -a "$GITHUB_WORKSPACE/." "$home/work/"
if [ -n "${MODEL_CONTEXT:-}" ]; then
  sudo cp -a "$MODEL_CONTEXT/." "$home/context/"
fi
sudo chown -R "$MODEL_USER:$MODEL_USER" "$home/work" "$home/context"
if [ -n "${MODEL_GIT_NAME:-}" ]; then
  sudo -u "$MODEL_USER" -H -- git -C "$home/work" config user.name "$MODEL_GIT_NAME"
  sudo -u "$MODEL_USER" -H -- git -C "$home/work" config user.email "$MODEL_GIT_EMAIL"
fi
echo "model: $home/work and $home/context belong to $MODEL_USER"
