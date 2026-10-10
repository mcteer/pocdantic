#!/bin/sh
# Install repository-local privacy checks for commits and pushes. This changes only
# this checkout's Git configuration; server-side protections remain separate.
set -eu
git config core.hooksPath .githooks
printf '%s\n' 'Privacy commit/push hooks installed'
