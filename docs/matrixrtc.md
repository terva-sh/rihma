# MatrixRTC control-plane groundwork

rihma has no calling or RTC session controller yet. The pinned upstream SDK
provides transport discovery; `rtc_discovery_test.go` proves that first
control-plane operation on local HTTP fixtures. No real call service is used
and discovered transport URLs are never contacted.

## Versions and dependency evidence

mautrix-go v0.31.0 exposes `RTCTransports`, `RespRTCTransports` and a
`livekit` transport with `livekit_service_url`. Discovery requires `/versions`:
`org.matrix.msc4143` selects the unstable endpoint, while
`org.matrix.msc4143.stable` selects `/_matrix/client/v1/rtc/transports`.
When both flags are set, the pinned implementation prefers unstable. With
neither flag (or no discovered versions), it refuses without an RTC request.
It has no typed `m.rtc.slot`, `m.rtc.member` or `m.rtc.encryption_key` support.
Existing `m.call.invite`/answer/candidates types describe legacy VoIP signaling,
not a MatrixRTC session implementation.

The [MSC4143 proposal](https://github.com/matrix-org/matrix-spec-proposals/blob/4d0e7315e650f27d86ddde194d82adf6596a4064/proposals/4143-matrix-rtc.md)
was inspected at `4d0e7315e650f27d86ddde194d82adf6596a4064`, and the
[MSC4195 LiveKit transport](https://github.com/matrix-org/matrix-spec-proposals/blob/dcb514de6bb0a904902c581aa718d82266005338/proposals/4195-matrixrtc-livekit.md)
at `dcb514de6bb0a904902c581aa718d82266005338`. These drafts differ from the
pinned SDK's experimental discovery schema: `transports` replaces
`rtc_transports`, and `m.livekit` plus `url` replaces `livekit` plus
`livekit_service_url`. A stable-looking endpoint or flag does not establish
support for the latest schema. The characterization test confirms the pinned
decoder silently treats the current draft's `transports` as an empty result;
fix schema negotiation upstream before exposing production discovery.

The focused discovery and full library checks build with cgo disabled and
`goolm`, using existing core HTTP/Matrix dependencies. No LiveKit, WebRTC or
codec implementation has been added or audited by this slice. The tests cover
authenticated unstable/stable requests, both-flag precedence, unsupported
capability, empty/unknown transport types, the current schema mismatch,
HTTP 403/`M_FORBIDDEN`, and in-flight cancellation with independently bounded
server cleanup. Unknown transport-specific fields are not preserved by the
pinned typed response and must be retained or refused in a future adapter.

## Session ownership and membership

Select and pin an explicit membership/transport dialect. The current MSC4143
draft defines room-state `m.rtc.slot` events and sticky `m.rtc.member`
events, using MSC4354's ephemeral map, rather than the older per-device
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
service. Current MSC4195 instead proposes authenticated homeserver
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

First fix and type upstream discovery/membership dialects. Then add an RTC
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
