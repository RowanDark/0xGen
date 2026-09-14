#!/usr/bin/env bash
# Fails if any tracked markdown file claims AI/LLM/ML capabilities the
# codebase doesn't have. See Issue 26 ("Remove AI claims from the rest of
# the repo"): there is no model call anywhere in this repository.
set -euo pipefail

pattern='ai-powered|ai-driven|artificial intelligence|machine learning'

mapfile -t md_files < <(git ls-files '*.md')
if (( ${#md_files[@]} == 0 )); then
  echo "No tracked markdown files found; skipping AI-claims guard."
  exit 0
fi

if matches=$(grep -rin -E "$pattern" -- "${md_files[@]}"); then
  echo "Forbidden AI/LLM/ML claims found in markdown:"
  echo "$matches"
  echo
  echo "Remove the claim, or describe the real (non-AI) behavior instead."
  exit 1
fi

echo "AI-claims guard passed."
