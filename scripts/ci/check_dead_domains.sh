#!/usr/bin/env bash
# Fails if the repository references a domain that has no registration/DNS
# records, so a dead placeholder link doesn't get copied into a real
# deployment. See issue #28.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

banned_domains=(
  "0xgen\.dev"
)

violations=0
for pattern in "${banned_domains[@]}"; do
  if matches=$(git grep -n -I --ignore-case -E "$pattern" -- . ':!scripts/ci/check_dead_domains.sh'); then
    if (( violations == 0 )); then
      echo "Found references to unregistered domains:"
    fi
    violations=1
    echo "$matches"
  fi
done

if (( violations )); then
  echo
  echo "These domains have no DNS records. Point to real infrastructure (e.g. the" \
       "GitHub Pages docs site or github.com/RowanDark/0xgen), use an" \
       "example.com/example.invalid placeholder, or register the domain before" \
       "referencing it."
  exit 1
fi

echo "Dead domain guard passed."
