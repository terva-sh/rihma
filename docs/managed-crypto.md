# Managed crypto shutdown

`Options.ManagedCryptoBackground` opts into cancellation and joining of crypto
workers before `Sync` returns and before `Close` releases the stores. Managed
clients are single-use: restore a fresh client after stopping. The default
retains upstream background behavior and permits the existing bot lifecycle.

The selected mautrix module must expose `EnableManagedBackground(context.Context)`
and `StopManagedBackground()`. Rihma detects this capability through an interface;
an unmodified dependency remains buildable. Requesting the option without the
capability returns `ErrManagedCryptoUnavailable` from `Open`, before session
access, state-directory creation or network activity.

Applications must explicitly select a reviewed, immutable public fork version
in their root `go.mod`, until the API is available upstream. Go ignores replacement
directives in dependencies, so a replacement in rihma alone does not select a
fork for its consumers. No fork version is selected by this document.

Stop and join application command producers before `Close`; the managed worker
API owns background crypto work, not arbitrary foreground commands. Sync owns
its backup uploader and SAS controller. Managed mode also stops UTD timers and
joins active UTD callbacks. Callbacks must honor cancellation and must not call
`Close` or wait for `Sync` from within a callback that shutdown is joining.

The dependency admission bound is 128 active tasks per machine. Overload can
refuse best-effort key work or delayed decryption; encrypted application journals
must retain those events for later recovery. Managed shutdown cancels pending
best-effort HTTP operations rather than promising their delivery. SAS expiry
sleepers may remain until their deadlines, but the stopped controller gates
store and client access; they do not retain ownership of the closed crypto DB.

Default-module checks test unavailable-capability refusal and ordinary behavior.
Explicit candidate-module checks must run the real helper missing-key regression:
holding its callback blocks `Sync` return until released, then later worker
admission and another `Sync` are refused. A skipped candidate test on upstream
is not evidence of managed-shutdown support.
