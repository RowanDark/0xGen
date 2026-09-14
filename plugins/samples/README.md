# Plugin samples (fixtures)

**This directory is not a plugin.** `plugins/samples/` itself has no
`manifest.json` and is excluded from plugin discovery via
`plugins/EXCLUDED_DIRS`. It holds fixture plugins used for documentation,
manual testing, and automated tests — they are not built, signed, or shipped
as production 0xgen plugins.

* `emit-on-start/` and `passive-header-scan/` are minimal, complete
  plugin examples (manifest, source, signature) runnable via
  `0xgenctl plugin run --sample <name>`. See `plugins/README.md` and
  `cmd/0xgenctl/plugin_run.go`.
* `invalid/` contains a deliberately invalid manifest used by manifest
  validation tests.
* `findings.jsonl` and `report.golden.md` are golden fixtures used by report
  generation tests.

Each subdirectory that represents a runnable sample plugin still has its own
`manifest.json` and is validated by CI like any other plugin manifest; only
the top-level `plugins/samples/` directory is exempt, since it is a fixture
container rather than a plugin.
