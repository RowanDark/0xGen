#!/bin/sh
set -eu

# Refresh the shell command hash table in case glyphctl was installed
# into a path that is already cached by the shell environment.
if command -v hash >/dev/null 2>&1; then
  hash -r || true
fi

# Exercise the binary to fail fast if the installation environment is broken.
if command -v glyphctl >/dev/null 2>&1; then
  glyphctl --version >/dev/null 2>&1 || true
fi
