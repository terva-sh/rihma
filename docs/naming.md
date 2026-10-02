# Why the command is terva-rihma

The command is **`terva-rihma`**. The repository and the connector are
`rihma`. They differ on purpose.

*Rihma* is Finnish for a thread or filament. A fungal *rihma* is a
hypha, and *rihmasto* is mycelium: a network of threads that spreads
quietly underground and connects everything it reaches. That is a fair
picture of Matrix federation, and threads are a first-class concept in
what this project builds.

## The command carries the terva prefix

A bare `rihma` on `PATH` would be a name anyone could ship next. The
`terva-` prefix keeps the command from ever colliding with an unrelated
`rihma`, and puts it in the same family as the terva harness and
`terva-lampi`. When it was named, `rihma` was unclaimed on npm,
crates.io, PyPI, and the Go module proxy, with no notable GitHub
project. The command does not depend on that staying true.

Nobody types the command anyway. terva runs it through `connector.json`
and `run.sh`, and operators name the connector, not the binary.

## The connector is rihma, and that is final

The manifest name, which terva uses to enable the connector and to name
its state directory, is `rihma`. It will not become `matrix`, the name
the Rust connector terva-conn-matrix uses.
[Decision 0002](decisions/0002-manifest-name.md) has the reasons. In
short, the drop-in gain is small, because moving from the Rust
connector already needs a new device and a new state directory, and
separate names let the two be installed side by side and rolled back by
switching which one is enabled.

## The library is terva.sh/rihma

The Go module is `terva.sh/rihma`, under the organization's vanity path,
as lampi's is. Its package name is `rihma`. The library has no terva in
it, so a caller outside terva imports a Matrix client named for what it
is, not for the harness it was first built for.
