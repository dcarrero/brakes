#!/bin/sh
# Seeded by brakes (agent-guardrails): the Codex cloud environment setup.
# Codex keeps the setup script in its environment settings, not in the
# repository: paste this file's content there. Setup runs with internet access
# and the environment's secrets; the agent phase runs without the secrets and,
# by default, without internet access
# (https://developers.openai.com/codex/cloud/environments).
#
# The steps are the stack packs' CI setup: their `run` steps in sh, in order.
# Steps that are GitHub Actions only are listed as comments: the Codex image
# provides those toolchains; pin their versions in the environment settings.
# This script fetches dependencies; it never runs the declared `verify`.
# The project owns this file once it exists.
set -eu

{{steps}}
