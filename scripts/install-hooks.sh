#!/bin/sh
set -eu
git config core.hooksPath .githooks
printf '%s\n' 'Privacy commit/push hooks installed'
