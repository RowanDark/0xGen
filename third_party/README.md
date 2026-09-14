# third_party/

This directory holds verbatim copies of upstream source code that is
licensed differently from this repository's own Apache-2.0 license
(see the root `LICENSE`). Each vendored module lives at a path that
mirrors its upstream Go import path (e.g. `golang.org/x/crypto` is
vendored at `third_party/golang.org/x/crypto/`), and carries its own
`LICENSE` file recording the terms that its source headers refer to.

See the root `NOTICE` file for the list of what is vendored here, where
it came from, and (where known) which upstream version it was taken
from.

## Why not everything BSD/MIT-licensed lives here

Code that is actively compiled as part of the main
`github.com/RowanDark/0xgen` Go module cannot live under
`third_party/<module>/` if that subtree also carries its own `go.mod`
(as `third_party/golang.org/x/crypto/` does) -- a nested `go.mod`
starts a separate Go module boundary, so the outer module can no
longer import packages from underneath it without a `replace`
directive pointing back at a real (or absent) upstream module.

`internal/netgate/http3/` is one such case: it is a hand-vendored,
not-yet-released copy of `golang.org/x/net/http3`, imported directly
by `internal/netgate`. It stays under `internal/` rather than moving
here, but still carries its own `LICENSE` file (BSD-3-Clause) next to
its source, consistent with the convention on this page. See the root
`NOTICE` for details.

## Adding a new vendored tree

1. Copy the upstream source verbatim, preserving its copyright headers.
2. Copy the upstream `LICENSE` file into the same directory.
3. Record the upstream module, the version or commit it was taken
   from, and the license in the root `NOTICE` file.
4. If the vendored code is not meant to be compiled as part of the
   main module, give it its own `go.mod` so it can't accidentally be
   imported without a `replace` directive.
