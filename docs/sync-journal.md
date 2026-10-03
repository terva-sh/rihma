# Durable application sync capture

Mautrix saves `next_batch` before processing a response, to avoid getting stuck
on a malformed event. That default remains unchanged when `Options.SyncJournal`
is nil. Applications with their own persistent timelines can opt into a stronger
boundary without replacing the crypto-aware syncer or adding another sync owner.

The `SyncJournal(ctx, response, since)` callback runs on the account's Sync
owner, before bot filtering and crypto/event dispatch. When supplied, rihma
stages mautrix's early cursor save in memory. It then calls the journal, dispatches
the response through the existing syncer, and finally commits the persistent
cursor. A journal or dispatch failure stops Sync without committing that cursor;
restart can receive the same batch again. A cursor commit failure also stops
Sync, so the batch may be repeated even after successful dispatch.

The callback must return only after its durable commit, honor cancellation,
and bound its storage/memory use. Copy or encode needed fields synchronously;
do not mutate or retain the response pointer. Raw responses can contain secrets
and untrusted message data. Never log them, and protect anything persisted.
A callback failure returns only `ErrSyncJournal`, and opted-in dispatch/cursor
failures use `ErrSyncDispatch`/`ErrSyncCursor`; private causes are discarded.

A useful application journal persists room/event records, ciphertext
placeholders, pagination/gap metadata and an application batch identity in one
transaction before returning. The caller owns idempotent materialization,
retention, replay of unmaterialized records and delayed re-decryption. An event
handler updating only a view is insufficient: a crash can occur after the
cursor commits but before the view/application state becomes durable.

This hook does not make application state exactly once, combine application
and crypto stores into one transaction, or make an HTTP send and sync echo one
transaction. Preserve stable event/transaction IDs and reconcile duplicates.
Synchronous event dispatch finishing also does not mean every delayed-key
crypto worker has finished; an application must preserve undecryptable records
and manage its callback shutdown boundary. Crypto-store error handling remains
mautrix's, including its own policy for errors in event handlers.

The core handler graph, full-client/bot policy, sync lock and resume store remain
in use. Register normal observers before Sync as usual. Do not call
ProcessResponse or SaveNextBatch manually alongside the sync owner.
