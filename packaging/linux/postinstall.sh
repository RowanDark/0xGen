#!/bin/sh
set -eu

# Refresh the shell command hash table in case 0xgenctl was installed
# into a path that is already cached by the shell environment.
if command -v hash >/dev/null 2>&1; then
  hash -r || true
fi

# Exercise the binary to fail fast if the installation environment is broken.
if command -v 0xgenctl >/dev/null 2>&1; then
  0xgenctl --version >/dev/null 2>&1 || true
elif [ -x /usr/local/0xgen/bin/0xgenctl ]; then
  /usr/local/0xgen/bin/0xgenctl --version >/dev/null 2>&1 || true
fi
