# Changelog

Phases (P0 to P8) are the stages of the implementation plan. Entries
that cite a ticket name it as `TKT-…`, an ID in the project's own
tracker.

## v0.1.0

- The connector uses the public terva v0.139.7 SDK. Thread text and media
  report their parent room and its DM/group kind when `chat_parents` is
  negotiated, so the host can apply the parent room's admission policy.

- **Speaker profiles, release archives, and operator docs (P8).**
  - **Speaker profiles:** with `speaker` set to `name_only` or `full`
    in `config.json`, the connector declares it, and a send with a
    speaker carries an MSC4144 profile (`com.beeper.per_message_profile`)
    with the speaker's id and name. `full` also uploads the avatar,
    once per speaker and file. If the avatar fails, the profile goes
    without it, so the send never fails. A speaker with no name, or a
    speaker sent while `speaker` is off, goes as plain text, as in
    terva-conn-matrix. `status` shows the setting.
  - **Release archives:** `just release-snapshot` builds an archive per
    platform with goreleaser, cgo-free and with goolm. Each unpacks to
    `rihma/` holding the binary, `connector.json`, and `run.sh`, which
    runs the bundled binary with no Go installed;
    `testing/release/verify.sh` checks that.
  - **Release workflow:** a `v*` tag builds, verifies, and publishes on
    the forge. CI and `just ci` build and verify a snapshot on every
    push.
  - **Docs:**
    - the README covers installing from an archive, setup against a
      real homeserver, every config key, and moving from
      terva-conn-matrix;
    - `docs/naming.md` explains the name;
    - `testing/DOGFOOD.md` is the operator walkthrough, adapted from
      terva-conn-matrix's.

- **Threads (P7).**
  - **Chat ids:** a thread is its own chat, `<room_id>;thread=<root_event_id>`.
    The format is private to rihma; the host never parses it.
  - **Starting:** `thread_start` opens a thread anchored at a message, or,
    with no anchor, rooted at its own starter message. Threads do not
    nest.
  - **Sending:** sends, asks, and attachments into a thread chat ride the
    thread. A `reply_to` is a real in-thread reply. Typing shows in the
    room.
  - **Receiving:** thread messages and attachments arrive under the
    thread's chat, kind `thread`, titled with the first line of the root
    (decrypted when encrypted, at most 60 characters). Stickers stay in
    the room, as in terva-conn-matrix.
  - **Correlation:** edits, reactions, and deletes about a thread message
    carry the thread's chat id. Edits and reactions find the thread of a
    message from before a restart by fetching it. Deletes cannot, because
    a redaction strips relations, so a delete of a thread message from
    before a restart arrives under the room.
  - **Declared:** `threads_out`.

- **Asks as a reaction widget (P6).**
  - **Rendering:** an ask posts its question with a legend, one
    `- emoji label` line per option, and seeds one reaction per option.
    The emoji is the option's hint, or else the next circled digit
    (①②③…).
  - **Answers:** a tap on a seed is an `attested` answer, with
    `RestrictTo` matched on the exact user id. A tap from anyone else
    is ignored and redacted where the bot has the power to. An
    answer's tap and its un-tap never also arrive as a reaction or a
    deletion.
  - **Closing:** `ask_close` withdraws the seeds and edits the outcome
    into the question. Closing an unknown or already-closed ask
    succeeds, as connproto specifies (terva-conn-matrix returns an
    error).
  - **Expiry:** an ask withdraws its seeds when it expires; a later
    tap is a plain reaction.
  - **Caveat:** reaction keys are cleartext even in encrypted rooms,
    so an option's hint must never carry anything sensitive.
  - **Declared:** `asks`.

- **Attachments both ways (P5, part 2).**
  - **Inbound:** images, audio, voice, video, files, and stickers
    arrive as a message with one attachment, downloaded and decrypted
    into the host's `data_dir`, with Matrix v1.10 captions honored.
  - **Limits:** a file over `max_attachment_mb` (default 64) is
    dropped on its declared size or, failing that, as it streams. A
    file whose encrypted hash does not match is dropped too. Neither
    leaves anything in `data_dir`.
  - **Outbound:** `send_image` and `send_file` upload the file,
    encrypted in encrypted rooms, with the caption as the body. The
    message type follows the file's type.
  - **Library:** `DownloadMedia` and `SendMedia`.
  - **Declared:** `attachment_kinds`, `SendsImages`, and `SendsFiles`.

- **Edits, deletes, and reactions both ways (P5, part 1).**
  - **Edits:** an edit arrives as `message_edited` under the original id,
    with its new text and entities.
  - **Reactions:** a reaction arrives as `reaction`. Its redaction is
    the same reaction with `removed: true`, credited to the reactor.
  - **Deletes:** any other redaction is `message_deleted`.
  - **Outbound:** the host can edit (rendered markdown, with a `"* "`
    fallback), react, remove a reaction, and delete. Removing a reaction
    after a restart finds it in the server's relations, decrypting where
    needed.
  - **Left rooms:** events from rooms the bot has left are not
    delivered.
  - **Declared:** `edits_in`, `edits_out`, `deletes_in`,
    `deletes_out`, `reactions_in`, `reactions_out`, and
    `MinEditInterval` 1 s.

- **Megolm key backup, as terva-conn-matrix has.**
  - **Setup.** Creating the recovery key also creates a key backup,
    signed by the master key, and stores its key in secret storage
    where Element looks for it. Restoring from the recovery key imports
    the backup and keeps uploading to it. An existing backup is never
    replaced.
  - **Uploads.** Every room key the bot holds is uploaded while it
    syncs, including keys for its own messages, so a device restored
    from the recovery key can read what the bot could.
  - **Status.** `setup` reports the backup, and `status` shows its
    version.
  - **Storage.** The backup key is sealed with the other session
    secrets.
  - **Supersedes P3.** P3 had decided not to upload backups; Drew chose
    parity.

- **Groups, membership, and mentions (P4).** Group messages carry
  `chat_title`: the room name, then the canonical alias, then empty.
  Unlike terva-conn-matrix there is no name computed from the members.
  - **Membership.** The bot's own membership becomes `chat_membership`
    frames. Joining is `added`, credited to the inviter. A kick, ban or
    leave is `removed`, credited to whoever did it. A profile change or
    a duplicate event emits nothing. The decision comes from each
    event's `unsigned.prev_content`, so a kick while the connector was
    down is reported on resume. The first-connect history sync
    announces nothing.
  - **Mentions.** Messages carry a `bot_mention` entity from any of:
    `m.mentions`, a pill (`matrix.to` or `matrix:u`), or a reply to one
    of the last 256 messages the bot sent. It is located by pill text,
    MXID, `@localpart`, display name, then localpart, counted in code
    points, and placed at 0/0 when it cannot be found. Another user's
    pill becomes a `mention` with that user id.
  - **auto_join** retries a failed join twice.
  - Declares `entities` and `chat_membership`.

- **Encryption setup in the connector (P3).** After logging in, `setup`
  offers to create the account's recovery key (the default, so piped
  provisioning gets one), restore from it, or skip, and then, if the
  device is still unverified, to wait for an emoji verification from
  another client. On an account that already has a cross-signing
  identity, creating one is refused and setup points at the restore
  option; rihma never replaces an identity. `verify` reads the verdict
  on the stored session, records it before offering the emoji wait, and
  exits non-zero unless verified. `status` shows the last verdict and
  which verb read it, or "not recorded".
- **One sync per state directory.** `Sync` takes an OS file lock, and a
  second sync on the same device fails with `ErrSyncInProgress` instead
  of splitting its to-device messages, which loses room keys. `verify`
  says to stop the bot first rather than sync beside it.
- **The library answers emoji verification.** `AwaitSAS` responds to a
  verification from another device of the same account and declines
  other users. `Verification` returns `verified`, `unverified`, or
  `no identity`.
- **The terva connector: DM text (P2).** `terva-rihma`, launched by
  `run.sh` from `connector.json`, speaks connector protocol 2 and refuses
  protocol 1. `setup` logs a new device in (the password is hidden on a
  terminal), `status` reads local files only and masks the token, and
  `reset` logs out best effort and never touches the host's
  `pairing.json` or `data/`. The access token and pickle key are sealed at
  rest through connsdk's `SealedState`. Inbound, only `m.text` is
  delivered, reply fallbacks are stripped, and `chat_kind` comes from
  `m.direct`, which an `is_direct` invite joins. Outbound text is
  markdown: `body` is the source as written and `formatted_body` is the
  HTML. Typing is refreshed every 20 s and stopped on `typing_stop`. A
  user id as a chat id addresses the joined DM with that user and never
  creates one. Declared features: `message_ids`, `chat_kinds`,
  `typing_stop`.
- **`just e2e` runs the connector under a fake host.** It ports
  terva-conn-matrix's `dm_round_trip_compliance` in an encrypted DM:
  identity, markdown out as a reply, reply fallback stripped, typing on
  and off, a message sent while the connector was down, `chat_kind`
  surviving a restart, and cold addressing.

- **The library core (P1).** `Open` restores a stored session without
  touching the network, or logs in and saves a new one; `Connect` starts
  end-to-end encryption; `Sync` runs with 1 s to 60 s backoff, stops on
  an invalid token, discards history only when there is no sync token,
  drops our own echoes, and resumes after downtime. `FileSessionStore`
  keeps the session in a 0600 file replaced atomically. Unable-to-decrypt
  reports are limited per room. `CreateRecoveryKey` refuses to replace an
  existing cross-signing identity; `RestoreFromRecoveryKey` signs a new
  device with it. `docs/architecture.md` records the API.
- **`just e2e` replaces `just e2e-spike`.** The live suite now runs on
  the library: the encrypted round trip, history discarded then live and
  downtime messages delivered, and a recovery key restored on a second
  device.
- **Repository skeleton (P0).** Module `terva.sh/rihma` on mautrix-go
  v0.31.0, a `justfile`, and Forgejo CI that vets, tests, and
  cross-compiles for linux/amd64, linux/arm64, darwin/arm64, and
  windows/amd64, all with `CGO_ENABLED=0 -tags goolm`.
- **A build without `-tags goolm` fails, and says why.** The error names
  `internal/buildwithtagsgoolm`. With cgo on it is the only error, which
  matters most where libolm is installed and the build would otherwise
  succeed on it. With cgo off mautrix's own libolm error prints too.
- **A runtime check that the Olm backend is goolm**, for `Open` to call.
- **CI fails if `mattn/go-sqlite3` is linked.** Without cgo it compiles to
  a stub that fails only at runtime, so no build would catch it.
- **The store runs on modernc.org/sqlite (P0).** `openStore` sets the
  same pragmas mautrix's cgo driver sets (foreign keys, WAL,
  `synchronous=NORMAL`, a 5 s busy timeout) plus immediate transactions,
  on every pooled connection. mautrix's crypto and state store upgrades
  run on it. Why modernc over ncruces is in
  `docs/decisions/0001-sqlite-driver.md`.
- **A throwaway Synapse for the live suite (P0).** `just synapse` starts
  Synapse and Element Web with plain `podman run` (or docker), adapted
  from terva-conn-matrix's compose setup. It publishes on 127.0.0.1 only,
  on ports that do not clash with the Rust harness, and fills the port
  into both configs. Under rootless podman its state stays owned by the
  invoking user, so `just synapse-clean` needs no sudo.
- **Encrypted DMs work without cgo (P0 exit).** `just e2e-spike` built a
  test binary with `CGO_ENABLED=0 -tags goolm`, shows its build settings,
  and runs an encrypted DM round trip between two mautrix clients on the
  modernc store against the throwaway Synapse. It checks both sides
  decrypted, and reads the server's raw timeline to confirm only Megolm
  ciphertext is there.
- **Store paths with `?`, `#`, or `%` open the right file.** The DSN is
  built as a URL; string concatenation silently opened a different file
  without the pragmas.
