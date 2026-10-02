# rihma

*Rihma* is Finnish for a thread or filament, and a fungal *rihma* is a
hypha; *rihmasto* is mycelium.

rihma is two things:

- **`terva.sh/rihma`**, a Go library that turns
  [mautrix-go](https://github.com/mautrix/go) into a cgo-free,
  end-to-end-encrypted Matrix client.
- **`terva-rihma`**, a terva chat connector built on that library,
  aiming at feature parity with
  [terva-conn-matrix](https://github.com/terva-sh/terva-conn-matrix).

**Status: early development.** The connector carries text in DMs and
groups, encrypted or not. It reports the bot's admission to groups and
mentions of it, and it verifies its device. It carries edits,
deletes, reactions, and attachments both ways. It renders asks as a
reaction widget, opens and follows threads, and can send as a named
speaker. Documents that cite a ticket name it as `TKT-…`, an ID in the
project's own tracker.

## Building

Library consumers building a chat client should set
`Options.SyncPolicy: rihma.SyncPolicyFullClient` to receive initial history and
self-sent timeline events, including messages sent by another device of the
same account. The zero value, `SyncPolicyBot`, retains connector history/echo
filtering. Both policies use the same crypto-aware sync lifecycle, state store,
and one-sync-per-device lock. Applications own timeline persistence and echo
reconciliation; see [the architecture](docs/architecture.md).

rihma builds only without cgo and on mautrix's pure-Go Olm backend:

```sh
CGO_ENABLED=0 go build -tags goolm ./...
```

A build without `-tags goolm` fails on purpose, with an error naming
`internal/buildwithtagsgoolm`. `just` lists the development tasks.
`just ci` runs lint, tests, cross-builds, and snapshot archive verification in
both public and development checkouts; it needs Go, just, and GoReleaser.
`just ci-internal` adds the ticket-store and release-tooling checks used by
internal CI; it needs git-ticket and Python 3 as well.

## The connector

terva launches `run.sh`, named by `connector.json`. A release archive
ships a prebuilt `terva-rihma` beside it, which `run.sh` runs; in a
checkout it builds `bin/terva-rihma` with Go whenever a source file is
newer than the binary.

### Installing

Each [release](https://github.com/terva-sh/rihma/releases) carries an
archive per platform, `terva-rihma_<version>_<os>_<arch>.tar.gz` (a zip
on Windows), with `checksums.txt` beside them. It unpacks to a `rihma/`
directory holding the binary, `connector.json`, `run.sh`, and these
docs, and needs no Go toolchain. Put that directory at
`$TERVA_HOME/connectors/rihma/` or link it:

```sh
tar -xzf terva-rihma_<version>_linux_amd64.tar.gz
terva bot link rihma/connector.json
```

From a checkout, `terva bot link connector.json` links the working tree,
and `just release-snapshot` builds the same archives into `dist/`
without publishing anything.

### Setup against a real homeserver

Give the bot a Matrix account of its own. Its device reads and sends as
that account, so do not share yours. Then:

```sh
terva bot setup --connector rihma
terva bot status
terva bot run --connector rihma
```

`setup` asks for the homeserver, the bot's user id, and its password,
and logs in as a new device named `terva`. The session lives in terva's
connector state, sealed at rest when terva has a recipient configured.
It then sets up encryption:
- on a new bot account it creates a recovery key and prints it once:
  **store it**. It also turns on key backup, so a device restored from
  that key can read what the bot could;
- on an account that already has a recovery key, give it that key;
- or verify the device by emoji from another client logged in as the
  bot.

`./run.sh verify`, run from the connector's directory with the bot
stopped, re-reads the verdict and offers the emoji verification again.
`status` shows the account, a masked token, the verification verdict,
and the key backup.

During `run`, decryption failures, transient connection or sync trouble,
and dropped attachments also surface in terva's operator output.
Decryption warnings are limited per room; sync and attachment warnings
each appear at most once per minute. Diagnostics stay in
`$TERVA_HOME/logs/connector-rihma.log`.

DM the bot to pair with it. Invite it to rooms and mention it there;
terva's admission flow gates every group. `terva bot reset --connector
rihma` logs the device out on the server and removes rihma's state. It
never touches terva's `pairing.json` or `data/`.

### Configuration

`$TERVA_HOME/connectors/rihma/config.json` holds the session that
`setup` writes, and these keys, which mirror terva-conn-matrix's:

- `auto_join`: `"always"` (the default) or `"never"`, whether the bot
  accepts invites at all.
- `max_attachment_mb` (default 64): the ceiling on inbound attachments.
  A larger file is dropped, on its declared size or as it streams.
- `speaker`: `"off"` (the default), `"name_only"`, or `"full"`. Off,
  terva prefixes a speaker's name to the message itself, which every
  client shows. On, rihma sends MSC4144 per-message profiles
  (`com.beeper.per_message_profile`) instead, and `full` uploads each
  speaker's avatar too. Turn it on once your clients render them. The
  connector reads it at start.

### Threads

A thread is a chat of its own, with the id
`<room_id>;thread=<root_event_id>`. With negotiated `chat_parents`, thread
text and media also report the containing room's ID and DM/group kind.
The host admits only the paired owner in DM threads and applies the
current parent policy to group threads. Owner-only thread restrictions
can narrow that policy. Thread revocation survives restart, and parent
revocation stops its threads. terva negotiates `chat_parents` from
v0.139.7. An older host gates each thread as a chat of its own and asks
nobody about it, so the owner sends `/approve` in the thread.

The format belongs to rihma and terva-conn-matrix; terva treats chat IDs as opaque. Edits and
reactions on thread messages carry the thread's id even after a restart.
A delete of a thread message from before a restart arrives under the
room's id instead, because a redacted event no longer says which thread
it was in.

### Asks

An ask is posted as its question with an emoji legend, and the bot
reacts to it once per option; a tap on one answers. Reaction keys are
not encrypted, even in an encrypted room, so an option's emoji says
nothing private.

### Moving from terva-conn-matrix

This is not an in-place upgrade:

- **A new device.** The Rust connector's crypto store cannot be read
  here, so rihma logs in as a new device with fresh verification.
  Restoring with the account's recovery key verifies it and, when the
  account has key backup, brings back the room keys.
- **A new connector.** rihma is enabled as `rihma`, not `matrix`
  ([decision 0002](docs/decisions/0002-manifest-name.md)), with its own
  state directory, `$TERVA_HOME/connectors/rihma/`. Run `setup` for it
  as for a new bot.
- **New pairings.** Pairings made under `matrix` do not carry over, so
  pair again by DMing the bot.
- **Rollback** is switching which of the two connectors is enabled.
  They can be installed side by side, but should not both run on the
  same account.

`testing/DOGFOOD.md` is the walkthrough to run before relying on it.

## The throwaway homeserver

`just synapse` starts a local Synapse and an Element Web already pointed
at it, on `127.0.0.1:18108` and `:18109`, with podman (or docker, via
`CONTAINER_ENGINE`). It is for tests only: open registration, no
federation, and all state under `testing/synapse/data`, which
`just synapse-clean` wipes. The ports and container names differ from
terva-conn-matrix's harness, so both can run at once.

## License

MIT. mautrix-go is MPL-2.0 and is used as a dependency.
