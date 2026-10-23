# MatrixRTC control-plane groundwork

rihma has no calling or RTC session controller yet. What ships is transport
discovery: `Client.DiscoverRTCTransports` asks the homeserver which MatrixRTC
transports it offers, in an explicitly negotiated wire dialect. No real call
service is used, and discovered transport URLs are never contacted.

```go
result, err := client.DiscoverRTCTransports(ctx) // stable, then unstable
switch {
case errors.Is(err, rihma.ErrRTCUnsupported):
    // The server offers no dialect this caller accepts.
case errors.Is(err, rihma.ErrRTCProtocol):
    // The server answered, but not in the negotiated dialect.
case err != nil:
    // A Matrix error (mautrix.HTTPError) or the context's error.
default:
    for _, transport := range result.Transports {
        if transport.LiveKit != nil {
            // Validated endpoint metadata. Do not contact it from here.
        }
        _ = transport.Raw // the complete wire object, unknown fields included
    }
}
```

## Discovery dialects

The pinned mautrix-go v0.31.0 has `Client.RTCTransports`, but it decodes only
the experimental `rtc_transports` body with a `livekit` transport and
`livekit_service_url`, and it decodes that body from the stable endpoint too.
A server that answers in the merged schema therefore decodes silently as an
empty list. rihma does not use that method. It uses mautrix's authenticated
generic HTTP through a narrow adapter, as Sliding Sync does, and forks no SDK
type. `rtc_discovery_test.go` keeps a characterization of the SDK behavior,
so a dependency upgrade that changes it is noticed.

[MSC4143](https://github.com/matrix-org/matrix-spec-proposals/blob/773fe468f9b4d9844a5cd482ef4a81fea3f9a520/proposals/4143-matrix-rtc.md)
and [MSC4195](https://github.com/matrix-org/matrix-spec-proposals/blob/6f9432eafe1a7dc40ccb28c6cbd30523878e9f15/proposals/4195-matrixrtc-livekit.md)
were inspected as merged into the proposals repository, at
`773fe468f9b4d9844a5cd482ef4a81fea3f9a520` and
`6f9432eafe1a7dc40ccb28c6cbd30523878e9f15`. Their discovery schema is the
same as at the revisions the earlier groundwork pinned
(`4d0e7315e650f27d86ddde194d82adf6596a4064` and
`dcb514de6bb0a904902c581aa718d82266005338`). The merged texts add an appendix
that records how the reference implementation's unstable endpoint differs.
rihma supports two dialects:

| | `RTCTransportsStable` | `RTCTransportsUnstable` |
| --- | --- | --- |
| Source | MSC4143/MSC4195 schema | The proposals' reference-implementation appendix; also what pinned mautrix decodes |
| `/versions` flag | `org.matrix.msc4143.stable` | `org.matrix.msc4143` |
| Endpoint | `GET /_matrix/client/v1/rtc/transports` | `GET /_matrix/client/unstable/org.matrix.msc4143/rtc/transports` |
| List | `transports`, required | `rtc_transports`; absent means none configured |
| LiveKit type | `m.livekit` | `livekit`, or `m.livekit` |
| LiveKit fields | `url` (SFU, `wss://`), required | `url` (SFU, `wss://`) and/or legacy `livekit_service_url` (`https://`); `m.livekit` requires `url` |

The caller passes the dialects it accepts, most preferred first; with none it
accepts stable, then unstable. Stable comes first because it is the merged
contract. A caller that wants the reference implementation even when both
are advertised passes `RTCTransportsUnstable` first. Each call fetches
`/versions` into its own value. It neither reads nor writes the embedded
mautrix client's `SpecVersions`, which is unsynchronized, so concurrent calls
and a concurrently starting Sync cannot race on it. Only the flags count.
No released spec version includes MatrixRTC, so none is inferred. When no
accepted dialect is advertised, discovery returns `ErrRTCUnsupported` without
a request.

A response is read only in the dialect that was negotiated. A body that
carries the other dialect's list key fails with `ErrRTCProtocol`, whether it
replaces or accompanies the expected key. rihma never falls back to another
dialect. In the stable dialect, `livekit` is an ordinary unknown type and
`livekit_service_url` is an unknown field. Both are kept raw and are not
typed.

Synapse 1.162.0 implements only the unstable dialect, behind
`experimental_features: msc4143_enabled`. It then advertises
`org.matrix.msc4143`, returns operator-configured transports verbatim under
`rtc_transports`, and returns `{}` when none are configured. Its v1 endpoint
answers 404 `M_UNRECOGNIZED`. The throwaway Synapse template enables the
feature with placeholder transports, and `rtc_discovery_e2e_test.go` checks
that rihma and the pinned SDK agree on it.

## Results, errors and limits

Discovery makes two requests: `/versions`, then the dialect's discovery
endpoint. It reports three outcomes:

- **Unsupported**: `ErrRTCUnsupported`. Any of these:
  - a dialect value is unknown;
  - `/versions` advertises no accepted dialect. This includes a body with no
    `unstable_features`, an empty one, and flags set to `false`. No discovery
    request is made.
  - the discovery endpoint answers 404 or `M_UNRECOGNIZED`. The mautrix
    `HTTPError` is wrapped as well.
- **Malformed**: `ErrRTCProtocol`. A successful response from either
  request is wrong in one of these ways:
  - `/versions` is not a JSON object, or a field it needs is wrong (see
    below);
  - the discovery body is not a JSON object, or its list is missing where
    required, `null`, or not an array;
  - the other dialect's list key is present;
  - a transport is not an object, or its `type` does not follow the Matrix
    common namespaced identifier grammar;
  - LiveKit endpoint metadata is invalid;
  - either response exceeds 64 KiB, or the discovery response lists more
    than 64 transports.

  A single bad transport fails the whole discovery; nothing is dropped
  quietly. These errors wrap no `HTTPError`, whose `Request` carries the
  access token, and quote no response content.
- **Empty**: a nil error with zero `Transports`. This is a genuine answer.

Both responses are parsed by exact key and JSON kind, not through Go's
struct decoding, which reads `null` as a zero value and matches keys
case-insensitively. A `null` the protocol does not allow is malformed, never
empty, unsupported or false:

- In `/versions`, `versions` is required and must be an array of strings.
  `unstable_features` may be absent; if present, it must be an object whose
  values are all `true` or `false`. A `null` for either, inside `versions`,
  or as any flag is malformed, even for a flag discovery does not read. So
  is `{}`, which lacks `versions`. A differently cased key, such as
  `UNSTABLE_FEATURES`, is an unknown key and advertises nothing.
- In the discovery body, the dialect's list may not be `null`. The other
  dialect's list key fails even when its value is `null`. A transport may
  not be `null`, and `type` must be a string.
- A LiveKit `url` or `livekit_service_url` that is present must be a
  string, so a `null` one cannot fall back to the other.
- Fields a dialect does not define are opaque and kept verbatim in `Raw`,
  `null` included. This covers every field of an unknown transport, and
  `livekit_service_url` on a stable `m.livekit`.

Sliding Sync's own `/versions` check still uses mautrix's decoding. It
reads a malformed body as no Sliding Sync support, which is the same
outcome as a missing flag.

Any other failure is returned as mautrix reports it, and cancellation
returns the context's error:

- Other HTTP statuses return an `HTTPError`. Examples are 403
  `M_FORBIDDEN`, 429, and 5xx. An error body over mautrix's 512 KiB error
  limit keeps its status.
- A `/versions` 404 is not `ErrRTCUnsupported`. It means a wrong
  homeserver URL or not a Matrix server, rather than a server without
  MatrixRTC.
- A network failure returns an `HTTPError` with no response.
- A failed OAuth refresh returns `mautrix.ErrFailedToRefreshToken`.

Both requests use the session's access token. Each is sent once, whatever
`DefaultHTTPRetries` or a `mautrix.WithMaxRetries` context says. The only
exception is mautrix's single re-send after it refreshes an OAuth access token
that the server rejected as stale. Neither request is logged, by the client's
logger or by a logger carried on the context. An OAuth refresh that discovery
triggers is mautrix's own request. It logs as the client is configured, and
rihma's request hook still omits its body. Sliding Sync's own `/versions`
check keeps the client's retry and logging defaults.

Each `RTCTransport` keeps `Type`, a detached copy of the complete wire object
in `Raw`, and `LiveKit` when the dialect defines the type. The order is the
homeserver's preference. A LiveKit `url` must be an absolute `wss://` URL with
a host. `livekit_service_url` must be an absolute `https://` URL with a host.
Neither may carry user information, a fragment or a backslash, or exceed 2048
bytes. A path and query are allowed. The error names the field, never its
value. Unknown transport types are not validated beyond `type`. Responses are
bounded at 64 KiB and 64 transports.

These are metadata only. rihma does not contact the SFU or the authorization
service, does not request MSC4195 `get_token`, and never sends a homeserver
credential to a discovered URL. Typed `m.rtc.slot`, `m.rtc.member` and
`m.rtc.encryption_key` messages are not implemented. The existing
`m.call.invite`, answer and candidates types in mautrix describe legacy VoIP
signaling, not MatrixRTC, and are kept separate. Discovery adds no
dependency: it builds with cgo disabled and `goolm`, on the existing HTTP and
Matrix packages. No LiveKit, WebRTC or codec implementation has been added or
audited.

## Session ownership and membership

Select and pin an explicit membership dialect. MSC4143 as merged defines
room-state `m.rtc.slot` events and sticky `m.rtc.member` events, using
MSC4354's ephemeral map, rather than the older per-device
`m.call.member` state model. A slot's application and encryption configuration
must be valid and open; the sender must still be joined to the room and its
membership event must remain eligible/sticky. Create a cryptographically
random member ID for each join of each device to each room/slot. Rejoining
gets a fresh ID. Do not derive or trust device identity from unverified JSON.

An RTC controller should consume the existing crypto-aware Sync owner and
durable application event capture; it must not start a competing sync loop.
Applications own slot creation/power-level policy and media presentation.
Keep session state bounded and expose safe member/transport metadata, never
credentials, SDP, media keys or message contents in diagnostic snapshots.

Renew membership before the dialect's sticky/lease duration expires. Arrange
server-side delayed leave before considering a join fully active, and restart
the delayed leave while healthy if supported. On leave or slot closure, stop
publishing, send the matching leave, cancel/settle the delayed event and join
renewal/auth/media workers before closing stores. On network loss retain a
safe cleanup receipt and rely on the supported server lease/delayed-leave
mechanism; do not claim remote cleanup merely because local shutdown finished.
If required sticky/delayed-event features are absent, refuse that dialect or
expose an explicit constrained mode with its cleanup limitations.

## Authorization and media-key boundaries

The older experimental LiveKit service URL points at a separate authorization
service. MSC4195 as merged instead specifies authenticated homeserver
`/rtc/livekit/get_token` endpoints with room/slot/member/SFU scope. Keep these
flows distinct. Never send a homeserver token to a discovered external URL.
Validate HTTPS/WSS origins and explicit operator policy before contacting
transport infrastructure; redirects must not forward credentials across origins.
Where an experimental flow requires an OpenID assertion, mint a short-lived,
audience/scope-appropriate assertion through the authenticated homeserver and
hold it only for the authorized exchange. Do not reuse password/session tokens.

Treat SFU JWTs as ephemeral capabilities bound to exact room/slot/member and
transport origin. Bound accepted lifetime, validate not-before/expiry and
refresh before expiry with clock skew, use bounded backoff and cancellation,
and discard them on leave or identity change. Client claim inspection is not
signature verification; the service must authenticate issuer/signature and
enforce grants. Reject overbroad or mismatched scope. Never persist or log JWTs
or authorization bodies. Revocation and leave/ban enforcement need a server/SFU
contract; expiry alone cannot prove a kicked participant lost access promptly.

Encrypted Matrix signaling is separate from encrypted media. Current
`m.per_member` derives recipient devices from cryptographically validated
membership events and shares sender keys through Olm-encrypted
`m.rtc.encryption_key` to-device messages. Reject cleartext key messages,
wrong room/member/sender/device bindings and unsupported encryption modes.
Apply cross-signing/trust policy, rotate on membership changes and periodically,
and bound delayed key activation and old-key retention. Keep keys in private
memory and clear buffers on teardown. The media engine must implement the
transport-specific derivation and frame encryption; the SFU receiving an
authenticated signaling connection does not establish end-to-end media secrecy.

## Work required for complete calls

Type the membership dialect explicitly, as discovery does, then add an RTC
session controller with deterministic local fixtures for join/renew/leave,
slot closure, permission changes, restart, delayed-event cleanup, credential
refresh failures and media-key binding/rotation. Pin the homeserver and
authorization/SFU dialect instead of depending on latest container images.

Choose and audit a pure-Go WebRTC/LiveKit media engine and every enabled
dependency, including codecs and frame encryption, across supported targets.
A mandatory cgo codec is a blocker. Applications may supply media through a
documented engine interface, but the library still must prove its own
signaling, lifecycle and encryption contracts. A disposable local SFU/auth
fixture and two-device encrypted media round trip, reconnect, leave/ban and
shutdown tests are required before complete MatrixRTC support is advertised.
No RTC connector feature string is declared by this groundwork.
