# Graduation dogfood: the real host driving the whole surface

Adapted for rihma from terva-conn-matrix's `testing/DOGFOOD.md`; the
rows are the same, because the two connectors promise the same surface.

The live suite (`just e2e`) proves the connector side of the wire. This walkthrough proves the other half — the real terva
host driving this connector, with a human in a real client — over the
**whole shipped surface**: DM and E2EE, groups and admission, edits /
deletes / reactions, attachments, asks, threads, downtime and crash
recovery. It replaces the P2-era checklist, which predated most of that.

Default setting: the **throwaway Synapse** — nothing touches your Matrix
ecosystem; both accounts live only on it. The same checklist is the
graduation run against a **real homeserver**: point `setup` at it (after a
`reset`), use a dedicated bot account, and log the human side in from
your usual client. Only §1–§2 differ.

Estimated time: ~30 minutes for the whole table; §5.1–5.3 alone is 10.

## 0. Prerequisites

- `terva` v0.139.7 or later on PATH (rows 17 and 34 say what an older
  host does differently), podman or docker running (throwaway route), and this
  repo checked out or a release archive unpacked (README, "Installing").
- A client that renders threads, reactions and edits — Element does (the
  bundled one below, or your own).

## 1. Start the throwaway homeserver (+ Element)

```bash
just synapse        # synapse http://127.0.0.1:18108, server_name: localhost
                    # element http://127.0.0.1:18109, already pointed at it
```

`just synapse-clean` later wipes it back to factory-fresh.

## 2. Create the two accounts

The bot account, via the API (registration is open on the throwaway):

```bash
curl -s -XPOST http://127.0.0.1:18108/_matrix/client/v3/register \
  -d '{"username":"tervabot","password":"tervabot-pw","auth":{"type":"m.login.dummy"}}' | head -c 200; echo
```

The human account: open **http://127.0.0.1:18109** → **Create account**
(any name, e.g. `drew`) — the bundled Element is preconfigured against
the throwaway, no homeserver editing, no email verification. For the
groups rows (§5.4) you want a **second** human account too — an
outsider who is not the owner.

## 3. Install and configure the connector

From this repo:

```bash
terva bot link $(pwd)/connector.json     # or rihma/connector.json from an archive
terva bot setup --connector rihma
#   homeserver URL: http://127.0.0.1:18108
#   user id:        tervabot
#   password:       tervabot-pw
#   e2ee:           [1] create a new recovery key (default — store the
#                   printed key; the throwaway makes it disposable) and
#                   or skip it and verify by emoji: log Element in AS
#                   tervabot and verify the "terva" device, or run
#                   ./run.sh verify later with the bot stopped
terva bot status                         # rihma block: MXID + masked token + e2ee + key backup
```

The connector state lands under `$TERVA_HOME/connectors/rihma/`:
`config.json` (the session inside it, its secrets sealed `enc:age:v2:…`
once `terva secret init` has run) and rihma's SQLite state and crypto
store. `terva bot reset --connector rihma` logs the device out
server-side and removes them, leaving terva's `pairing.json` and
`data/` alone.

## 4. Run the bridge — with approvals ON

```bash
terva bot run --connector rihma --approval ask
```

A bot defaults to yolo (it runs its tools without asking); `--approval
ask` is what makes the **ask widget** fire (§5.6), and the admission
flow (§5.4) uses the same widget. From inside a running TUI,
`/connect rihma` works too, but the flags above are the daemon's.

Logs: `$TERVA_HOME/logs/connector-rihma.log` (or `terva bot logs
--follow` for a background `start`). The first connect after `setup`
discards the history that predates it, once; every later start resumes
from the stored sync token.

## 5. The checklist

Pass criteria are written from the human's seat. Where a row says "the
agent mentions…", ask it — `what just happened in this chat?` is enough;
the host hands it chat events as bracketed `[chat event: …]` notes.

### 5.1 Pairing and DM basics

| # | check | pass looks like |
|---|---|---|
| 1 | Pair | from Element, start a DM with `@tervabot:localhost` and say hello; the bot auto-joins, the first sender claims the bridge (host-side — follow the confirmation it sends) |
| 2 | Round trip | your message becomes an agent turn; the reply lands in the DM |
| 3 | Markdown | ask for a bulleted list with a code block; it renders as formatting in Element, not as literal asterisks |
| 4 | Reply mapping | hover-reply to a bot message and ask a follow-up; the agent treats it as a normal prompt referring to that message, nothing mangled |
| 5 | Typing | "tervabot is typing…" shows while the agent works and **clears as the reply lands** (`typing_stop`; on a host without it the indicator lingers up to ~30 s) |
| 6 | Built-ins | `/status` answers in-chat; `/stop` cancels a running turn |

### 5.2 Recovery

| # | check | pass looks like |
|---|---|---|
| 7 | Downtime recovery | Ctrl-C terva; send a DM while it's down; restart with the same command. The missed message **arrives and becomes a turn**, and fresh traffic flows. Only the first-ever connect after `setup` discards history; every later connect resumes from the store's sync token |
| 8 | Crash recovery | `kill -9` the `terva-rihma` process (not terva); terva restarts it within seconds (watch the log); the conversation continues, nothing delivered twice |

Row 7 is the sharp one: terva-conn-matrix's PLAN.md §9 calls
double-delivery the worst failure mode. Recovery is bounded by the server's recent
window: a long outage delivers each room's most recent messages, not
the whole gap.

### 5.3 E2EE

| # | check | pass looks like |
|---|---|---|
| 9 | Encrypted DM | enable encryption in the DM (Element: room settings → Security & Privacy); the conversation keeps working both ways and Element shows the shield on both sides' messages |
| 10 | Encrypted downtime | repeat row 7 in the encrypted DM; the missed ciphertext decrypts on arrival (its room key rides the queued to-device traffic) |
| 11 | Unable-to-decrypt | (optional) log Element out and back in AS the human, send before keys re-share; terva's operator output warns about the room's unable-to-decrypt burst, diagnostics reach the connector log, and the connector never crashes and recovers on the next message |

### 5.4 Groups and admission

Use the outsider account where it says "outsider".

| # | check | pass looks like |
|---|---|---|
| 12 | Invite → admission ask | create a named room and invite the bot; it auto-joins and **the owner's DM gets the admission ask**: a message with a legend and three seeded reactions — ① Approve (mention-only), ② Approve (all messages), ③ Ignore (the host sends no hints for these, so every option gets the circled-digit fallback) |
| 13 | Cold addressing | (optional) restart terva, and invite the bot to a fresh room **before** sending any DM in that host run; the ask still lands in the existing DM (a user-id-addressed frame resolves to the `m.direct` room) |
| 14 | Approve | before tapping, have the outsider @-mention the bot in the group once (and send one plain line); then tap ① on the ask. The seeds are withdrawn, the outcome renders into the question message, the DM confirmation says "starting with the message that was waiting", and the bot **answers the mention** in the group — the plain line is not replayed (mention-only). terva #867 |
| 15 | Mention gate | in the group, a plain message does nothing; an @-mention of the bot (Element's pill) becomes an agent turn, attributed `@name:` |
| 16 | Outsider | the outsider @-mentions the bot in the admitted group; the agent answers (group reach), but the outsider's `/status` gets no answer — owner-only |
| 17 | Kick | remove the bot from the room; terva revokes the chat, and a re-invite runs admission again with one fresh ask. Needs terva v0.139.6 or later: v0.138 asks again only after a restart, because it does not release the chat's ask claim on removal |
| 18 | Encrypted group | repeat rows 12, 14, 15 in a room with encryption turned on before the invite; identical behavior, the mention arrives decrypted with its entity |

Held messages expire after 10 minutes and only the last 5 per chat are
kept (proposals §7) — approve within that window for row 14's replay.

### 5.5 Message events and attachments

| # | check | pass looks like |
|---|---|---|
| 19 | Edit before pickup | while the agent is busy on one message, send another and edit it before its turn starts; the agent answers the **edited** text |
| 20 | Edit after | edit a message the agent already answered; the agent mentions the edit on your next prompt |
| 21 | Delete queued | while the agent is busy, send a message and delete it before its turn; it **never becomes a turn** |
| 22 | Reaction as note | react 👀 to a bot message, then ask what happened; the agent mentions your reaction. Remove it; asked again, it knows it was removed |
| 23 | No bot echo | after §5.6 row 28, ask what chat events the agent saw; the bot's own seeded reactions, their withdrawal, and the outcome edit of its own message must **not** come back as notes (echo hygiene — the host drops them only because we return `result.message_id`) |
| 24 | Bot-originated events | the host `Loop` has no caller for outbound `edit`/`react`/`delete` yet (streaming edits are tracked host work) — nothing to check here; all three are pinned by the live suite |
| 25 | Inbound image | send a photo in the DM and ask what's in it; a vision-capable model describes it (file lands under the host's `data_dir`, never inline) |
| 26 | Inbound file | send a text file; the agent reads it with its tools |
| 27 | Oversize | (optional) set `max_attachment_mb: 1` in `config.json`, restart, send a larger file; it is dropped with a rate-limited warning in terva's operator output, diagnostics stay in the connector log, and nothing is left in `data/`. The scripted row requires a fresh operator warning and a connector diagnostic for that attachment's event ID; a log-only warning fails |

Outbound `send_image`/`send_file` are pinned byte-exact by the live
suite; here they show up only if your agent setup produces a file to
send (image generation, an extension that emits one).

### 5.6 Asks (approvals and questions)

Requires `--approval ask` (§4).

| # | check | pass looks like |
|---|---|---|
| 28 | Approval widget | ask the agent to run a shell command (`run \`date\``); the DM gets the approval question with a legend and three seeded reactions — 👍 Approve, ① Always (this tool) (no hint upstream, so the circled-digit fallback), 👎 Deny; tap 👍 → the tool runs, the seeds are withdrawn, `Approve — @you` renders into the question |
| 29 | Deny | again, tap 👎; the call is refused and the agent reports the denial |
| 30 | Expiry | again, ignore it; after the timeout the widget closes itself and the call is **denied** (fail-closed) |
| 31 | Attestation | again, tap ① (Always); the durable grant is **accepted** and the next call of that tool runs without asking — the host requires `attested` answers for allow-always, and a Matrix reaction is a signed event, so ours qualify |
| 32 | Imposter | in an admitted group, get the outsider to make the agent call a tool; the approval goes **only to the owner's DM** (terva's `AskTarget` sends every non-DM turn's approval there), none appears in the group, and the owner's tap closes it |
| 33 | Agent question | ask the agent to ask you a multiple-choice question with 3 options; it arrives as the widget with ①②③-style hints; answer by reaction. Ask for a free-text or multi-select question; that one arrives as **numbered plain text** — deliberate (the floor is the richer path there) |

### 5.7 Threads

| # | check | pass looks like |
|---|---|---|
| 34 | Thread in | in Element, start a thread on a bot message and post in it: the reply arrives **in the thread**, and the thread is its own conversation (its context starts from the root snippet, not the room's history). From terva v0.139.7, with `chat_parents`, a thread in the owner's DM is admitted as the DM is. An older host gates the thread as its own unadmitted chat and asks nobody, so send `/approve all` in the thread first |
| 35 | Thread events | edit, react to, and delete messages inside the thread; each behaves as in §5.5, scoped to the thread — the room conversation never sees them |
| 36 | Thread after restart | restart terva, edit a thread message sent before the restart; the edit still lands in the thread (re-derived from the event's relation). A **delete** of a pre-restart thread message degrades to the room — a known limitation (README) |

Outbound `thread_start` (`threads_out`) has no host caller yet — the
host `Loop` never opens threads today — so it is proven only by the
live suite's thread scenario.

### 5.8 Speaker profiles (optional)

Only visible when the host sends a speaker (personas / cast). Set
`"speaker": "name_only"` (or `"full"`, for avatars too) in
`config.json`, restart; `terva bot status` shows it, the bot's messages
carry `com.beeper.per_message_profile`, and a client that renders
MSC4144 shows the speaker's name per message. Off, the host prefixes
`**Name:**` itself. Skip if you don't run personas.

### 5.9 Hygiene

| # | check | pass looks like |
|---|---|---|
| 37 | Status | `terva bot status` shows the rihma block with the token masked |
| 38 | Sealed at rest | with `terva secret init` done: `config.json`'s `session.access_token` reads `enc:age:v2:…`; the log never prints a token or message content |
| 39 | Reset | `terva bot reset --connector rihma` logs the device out (Element, as tervabot, no longer lists "terva") and removes rihma's state from `connectors/rihma/`, leaving `pairing.json` and `data/` |

## 6. Afterwards

```bash
terva bot reset --connector rihma    # log out + wipe connector state
just synapse-clean                   # wipe the homeserver
```

Anything that fails here is a bug in this repo unless a row says
otherwise. File it as a ticket with the transcript from
`$TERVA_HOME/logs/connector-rihma.log` and what you saw in the room.
Before calling something a host gap, read terva-conn-matrix's
`docs/connproto-proposals*.md` and this repo's
[docs/connsdk-proposals.md](../docs/connsdk-proposals.md).

## 7. Scripted humans

### Live operator-warning regression

`just e2e` includes a real-host warning scenario when `RIHMA_E2E_TERVA`
points at a terva v0.139.7 or later binary:

```bash
RIHMA_E2E_TERVA=/path/to/terva just e2e
```

The scenario registers fresh accounts on the throwaway Synapse, starts
the real host with an isolated `TERVA_HOME`, and uses a local fake model
endpoint. It needs no provider credentials and never calls a remote
model. It checks attachment warnings against fresh connector diagnostics,
undecryptable-event bursts and their aggregated counts, warning rate
limits, queued-message recovery after a connector-only proxy outage,
and valid traffic after each failure. It also runs scripted row 27 and
checks operator notices for leaked fixture content or session secrets.
The generated session file is read only for that check; its values never
appear in the test report.

Without `RIHMA_E2E_TERVA`, this additional scenario is explicitly skipped;
the rest of the live suite still runs. The operator scenario refuses a
homeserver outside HTTP loopback.

For a concurrent isolated harness, set `SYNAPSE_NAME`, `ELEMENT_NAME`,
`SYNAPSE_DATA_DIR`, `SYNAPSE_PORT` and `ELEMENT_PORT` before running
`just e2e`. Use unused container names and loopback ports, and a temporary
data directory of your own. The same settings apply to `synapse-status`,
`synapse-down` and `synapse-clean`. Defaults still use `rihma-synapse`,
`rihma-element`, ports 18108/18109 and `testing/synapse/data`.

### Checklist driver

`testing/dogfood` plays both humans through two password accounts, so
the table can run without a person at a client. It drives every row it
can through the Matrix API against the real `terva bot run`, and writes
a report marking each row PASS, FAIL, SKIP, or REVIEW. REVIEW means the
outcome is a model's wording and needs a reader. It cannot see how a
client renders anything, so rows 3 and 9 still want eyes on Element.

```bash
go run -tags 'goolm dogfood' ./testing/dogfood \
  -hs https://matrix.example.org -bot @bot:example.org \
  -owner @owner:example.org -owner-password-file ~/owner.password \
  -stranger @outsider:example.org -stranger-password-file ~/outsider.password \
  -state "$SCRATCH/humans" -report "$SCRATCH/report.md" \
  -launch 'cd "$SCRATCH/cwd" && exec terva bot run --connector rihma --approval ask' \
  -pairing "$TERVA_HOME/connectors/rihma/pairing.json" \
  -connector-log "$TERVA_HOME/logs/connector-rihma.log"
```

With `-launch` the driver owns the bot, so stop any other `terva bot
run` for the connector first. With `-pairing` it sets the operator's
pairing aside so the scripted owner can claim with `/start`, and puts
it back at exit. Rows 11, 13, 24, and 39 are always skipped, each for
the reason the report gives. Row 31 runs only with `-allow-always`,
because it grants the tool for the rest of the terva session.
`-approve-threads` sends `/approve all` in row 34's thread first, for a
host older than terva v0.139.7. `-rows 2,3,28` runs a subset; keep row 2
in a subset with the group rows, because terva learns the owner's DM
from a message there, not from the `/start` claim, and asks nothing
until it has.
`-skip 37` leaves rows out. `-config` names the connector's
`config.json` when it does not sit beside the pairing file.

To run against the throwaway Synapse without disturbing a real bot,
keep the connector's state in a scratch home and the host's in your
own. Use a one-run manifest named, say, `rihma-synapse`, whose `exec` is
a script that exports `TERVA_HOME=<scratch>` and execs this `run.sh`.
Launch with `--connector rihma-synapse --connector-manifest <it>`, and
pass `--provider` and `--model`, because a newly named bot connector
has no provider of its own yet. Point `-pairing` at the host's
`connectors/rihma-synapse/pairing.json` and `-config` at the scratch
home's `connectors/rihma/config.json`. Skip row 37, which reads the
installed `rihma`.
