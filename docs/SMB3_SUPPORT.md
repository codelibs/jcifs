# SMB2 / SMB3 Support Status

What jcifs actually supports, read off the source tree rather than off a plan.
Current as of 3.0.4-SNAPSHOT.

This is the authoritative statement of protocol support. The documents under
[proposals/smb3/](proposals/smb3/) describe features that are **not**
implemented; they are design proposals, not descriptions of the code.

## How to read this

| Label | Meaning |
| --- | --- |
| **Supported** | Reachable from normal client use and exercised on the wire. |
| **Partial** | Works, with a limitation called out in the notes. |
| **Not functional** | Code exists and may look complete, but nothing reaches it, or it fails when reached. Do not rely on it. |
| **Not implemented** | Only a protocol constant exists, or nothing at all. |

**"Not functional" is the label that matters.** Several areas contain complete
request/response classes, encoders, decoders and setters that no production code
calls. Finding a matching class or constant in the source tree is not evidence of
support. Where that is the case below, the specific dead end is named.

## Short version

jcifs is a solid SMB2/SMB3 **file access** client: negotiate, authenticate, sign,
encrypt, open, read, write, enumerate, query and set metadata, watch for changes,
resolve DFS, and copy server-side within a share. SMB 3.1.1 is negotiated by
default, and SMB3 signing, pre-authentication integrity and transform encryption
all work against real servers.

The rest of the "SMB3 advanced feature" bucket — leases, oplocks, durable and
persistent handles, multi-channel, directory leasing, RDMA, witness, compression
— is either absent or present only as unreachable scaffolding.

## Protocol versions

| Dialect | Status | Notes |
| --- | --- | --- |
| SMB1 / CIFS | Supported | Legacy; also the default multi-protocol negotiate bootstrap. |
| SMB 2.0.2, 2.1 | Supported | |
| SMB 3.0, 3.0.2 | Supported | Signing and AES-128-CCM encryption. |
| SMB 3.1.1 | Supported | Pre-auth integrity, negotiate contexts, AES-128-GCM encryption. |

Selection is controlled by `jcifs.client.minVersion` (default `SMB1`) and
`jcifs.client.maxVersion` (default `SMB311`), so **SMB 3.1.1 is reachable with
stock defaults**. Set `jcifs.client.useSMB2Negotiation=true` to skip the SMB1
bootstrap. The server-selected dialect is range-checked; an unknown or
out-of-range dialect fails the connection.

## Integrity and authentication

| Feature | Status | Notes |
| --- | --- | --- |
| Signing, HMAC-SHA256 (SMB 2.x) | Supported | |
| Signing, AES-128-CMAC (SMB 3.x) | Supported | Via Bouncy Castle. |
| Inbound signature verification | Supported | Fail-closed: an unsigned response where a digest is in force also counts as a failure. Skipped for `STATUS_PENDING` interim responses, and for encrypted messages, which the AEAD tag authenticates instead (MS-SMB2 3.1.4.1). |
| Pre-auth integrity, SHA-512 (SMB 3.1.1) | Supported | Chained over NEGOTIATE and every non-final SESSION_SETUP and fed into signing-key derivation, so tampering surfaces as a signature failure. Skipped for anonymous sessions. |
| Secure negotiate (`FSCTL_VALIDATE_NEGOTIATE_INFO`) | Supported | Sent on tree connect for signed SMB 2.1–3.0.2 sessions. Security mode, capabilities, dialect and server GUID are compared, and a mismatch disconnects the transport. Not used on 3.1.1, which relies on pre-auth integrity. Knob: `jcifs.client.requireSecureNegotiate`, default `true`. |
| Authentication: NTLMSSP, Kerberos, SPNEGO | Supported | |
| AES-128-GMAC signing (SMB 3.1.1, optional) | Not implemented | No `SIGNING_CAPABILITIES` negotiate context either. |

### `jcifs.client.signingPreferred` does not enable SMB2 signing

Despite the name, `signingPreferred=true` does not make the SMB2/SMB3 client
sign. `SmbSessionImpl.isSignatureSetupRequired()` consults only `signingEnforced`
and the server's SIGNING_REQUIRED bit. On SMB2 the config flag is used only to
raise an error when signing is wanted but no session key is available, and to set
an SMB1 header flag.

**Use `jcifs.client.signingEnforced=true` when signing must be guaranteed.**
`jcifs.client.ipcSigningEnforced` defaults to `true`, so IPC$ traffic is signed.

## Encryption

Supported since 3.0.4, and **off by default**. Set
`jcifs.client.encryptionEnabled=true` to opt in. Once enabled, encryption is
applied automatically to any session or share the server marks as requiring it;
nothing else in the API changes.

| Feature | Status | Notes |
| --- | --- | --- |
| AES-128-CCM (SMB 3.0, 3.0.2) | Supported | |
| AES-128-GCM (SMB 3.1.1) | Supported | Preferred when the server offers both. |
| `ENCRYPTION_CAPABILITIES` negotiation | Supported | Sent only when encryption is enabled. |
| Per-session encryption (`SMB2_SESSION_FLAG_ENCRYPT_DATA`) | Supported | |
| Per-share encryption (`SMB2_SHAREFLAG_ENCRYPT_DATA`) | Supported | Recorded on tree connect; a plaintext share on the same connection stays plaintext. |
| Encryption of compound chains | Supported | The whole chain is wrapped in one transform header. |
| AES-256-CCM / AES-256-GCM | Not implemented | Not negotiated. |

How it behaves:

- Outgoing messages are wrapped in an SMB2 TRANSFORM_HEADER by `doSend`.
  Incoming `0xFD 'SMB'` frames are recognised by `peekKey`, which resolves the
  session from the header's `SessionId`, decrypts, and dispatches on the message
  id read from the *decrypted* header.
- Encrypted messages are not signed, and their signatures are not verified — the
  AEAD tag authenticates them. The session id in the decrypted header is checked
  against the transform header.
- Where encryption is required but unavailable, the client fails with a clear
  error rather than falling back to plaintext.
- A transform frame for an unregistered session, or one that fails to decrypt,
  tears down the transport rather than skipping the frame. This fails closed, and
  differs from an unknown plaintext message id, which is skipped.

### History

Before 3.0.4 this did not work at all. `Smb2EncryptionContext` was constructed
and never used, `doSend` wrote plaintext unconditionally, and a transform header
on the receive path was mistaken for a desynchronised stream. Enabling encryption
could break connections that worked in plaintext, and a share that required
encryption failed authentication. The cipher primitives were also non-conformant
— a reversed ProtocolId, a 52-byte AAD instead of 32, 16-byte nonces, and an
AES-128-CCM path that could not decrypt its own output — none of which the unit
tests caught, because they only decoded their own encoded output.

If you are on 3.0.3 or earlier, leave `encryptionEnabled` off. See #70, #71 and
the fix in #92.

## Negotiate contexts (SMB 3.1.1)

| Context | Status |
| --- | --- |
| `PREAUTH_INTEGRITY_CAPABILITIES` (0x1) | Supported, SHA-512 only. A response without it fails the connection. |
| `ENCRYPTION_CAPABILITIES` (0x2) | Supported, AES-128-CCM and AES-128-GCM. Sent only when encryption is enabled. |
| `COMPRESSION_CAPABILITIES` (0x3) | Not implemented |
| `NETNAME_NEGOTIATE_CONTEXT_ID` (0x5) | Not implemented |
| `TRANSPORT_CAPABILITIES` (0x6) | Not implemented |
| `RDMA_TRANSFORM_CAPABILITIES` (0x7) | Not implemented |
| `SIGNING_CAPABILITIES` (0x8) | Not implemented |

Unknown context types received from a server are ignored rather than treated as
errors.

## SMB2 operations

| Command | Status | Notes |
| --- | --- | --- |
| NEGOTIATE, SESSION_SETUP, LOGOFF | Supported | |
| TREE_CONNECT, TREE_DISCONNECT | Supported | |
| CREATE, CLOSE | Supported | Compound (related) requests are used for open+query+close sequences. |
| READ, WRITE | Supported | See [Throughput](#throughput-and-credits) for size limits. |
| QUERY_INFO, SET_INFO | Supported | |
| QUERY_DIRECTORY | Supported | Streaming enumeration. |
| CHANGE_NOTIFY | Supported | Via `SmbResource.watch(int, boolean)`. Blocking. |
| IOCTL | Partial | Reachable FSCTLs: DFS_GET_REFERRALS, PIPE_PEEK, PIPE_TRANSCEIVE, SRV_COPYCHUNK(_WRITE), SRV_REQUEST_RESUME_KEY, VALIDATE_NEGOTIATE_INFO. The other defined FSCTL constants are never sent. |
| Async / `STATUS_PENDING` interim responses | Supported | |
| FLUSH | Not functional | `Smb2FlushRequest` exists and is referenced nowhere. `SmbFileOutputStream` does not override `flush()`, so flushing is a silent no-op and no durability barrier is sent. |
| LOCK | Not functional | `Smb2LockRequest` exists and is referenced nowhere. **There is no byte-range locking API** on `SmbResource`, `SmbFile` or `SmbRandomAccessFile`. |
| ECHO | Not functional | `Smb2EchoRequest` exists and is referenced nowhere. There is no keepalive or liveness probe. |
| CANCEL | Not functional | `Smb2CancelRequest` is fully built and wired into the send path, but `createCancel()` is never invoked. Nothing can cancel an in-flight request — including a pending CHANGE_NOTIFY, as `SmbWatchHandle`'s own javadoc notes. |
| OPLOCK_BREAK | Not functional | See below. |

## Caching, oplocks and handles

None of this works. It is the area most likely to be mistaken for working code.

| Feature | Status | Notes |
| --- | --- | --- |
| Oplock request on CREATE | Not functional | `setRequestedOplockLevel()` has no production caller, so **every CREATE requests oplock level NONE**. |
| Granted oplock level | Not functional | Decoded into a field whose getter has no caller. |
| Oplock break notification | Not functional | The notification is decoded and dispatched, but `handleNotification` is a single `log.info` line. No cache is invalidated, no handle is touched, and there is no override anywhere. |
| Oplock break acknowledgement | Not implemented | There is no acknowledgement message class at all. The client cannot answer a break. |
| SMB3 leases | Not implemented | Two unused constants. A real lease-break frame would fail the notification decode (structure size 44 vs the expected 24) and tear down the transport. |
| Directory leasing | Not implemented | Unused capability constant; depends on leases. |
| Durable / persistent handles | Not implemented | No DHnQ/DH2Q/DHnC/DH2C contexts, no app instance id, no handle reconnect path. |
| Create contexts (the framework itself) | Not functional | The request side encodes correctly: `Smb2CreateRequest.setCreateContexts()` lays contexts out as MS-SMB2 2.2.13.2 requires, and `CreateContextIT` checks that a real server answers each one. But nothing outside the tests calls it, and `Smb2CreateResponse.createContext()` is `return null`, so a context in a response is skipped. Before 3.0.4 no context could be sent at all — `size()` left out each context's header and name, so the request failed before it was sent — and the encoder also zeroed every `Next` and undercounted `CreateContextsLength`. |

The last row is the blocker for the three above it: leases, durable handles and
persistent handles all ride on create contexts. Contexts can now be sent, but a
lease or durable handle response still cannot be recognised, so none of the three
can be implemented without first decoding those response contexts.

## Throughput and credits

| Aspect | Status | Notes |
| --- | --- | --- |
| Maximum read size | **64936 bytes** | Hard cap. |
| Maximum write size | **64904 bytes** | Hard cap. |
| `SMB2_GLOBAL_CAP_LARGE_MTU` | Not implemented | The client never advertises it, so the server's LARGE_MTU bit is masked off during negotiate. |
| `creditCharge` on outgoing requests | Not functional | The field has no setter and ships as 0 on every request; `getCreditCost()` is hardcoded to 1. Credits are accounted one per request regardless of payload size. |
| Credit accounting | Supported | Per connection. |
| Connection pooling | Supported | See below. |

The read and write ceilings follow from `jcifs.client.transaction_buf_size`
(default `0xFFFF`, less 512 = 65023) minus per-message overhead, and apply **no
matter what the server offers** — a Windows server typically offers 8 MiB.
Reads and writes are chunked at exactly those sizes.

### Multiple connections to one server

There is no SMB3 multi-channel (see below), but the transport pool will open
additional TCP connections to the same host once a connection reaches
`jcifs.client.ssnLimit` sessions (default **250**). Lowering that value spreads
sessions across more connections; `ssnLimit=1` gives one connection per session.
These are independent connections, not bound channels of one session.

## Other features

| Feature | Status | Notes |
| --- | --- | --- |
| DFS referral resolution | Supported | On by default (`jcifs.client.dfs.disabled=false`). Uses `FSCTL_DFS_GET_REFERRALS`; the `_EX` variant is not used. |
| Server-side copy (copychunk) | Partial | `SmbFile.copyTo` uses `FSCTL_SRV_COPYCHUNK` **only when source and destination resolve to the same tree connection**. Cross-share and cross-server copies silently fall back to read/write streaming. |
| Named pipes | Supported | Transceive and peek. |
| Symbolic links / reparse points | Not implemented | `STATUS_STOPPED_ON_SYMLINK` does not appear in the source tree. The SMB2 error response body *is* captured into `errorData`, so the symlink target is in memory, but nothing reads it: opening a path that crosses a symlink fails with an opaque error. |
| Multi-channel | Not functional | One unused capability constant, an unused `FSCTL_QUERY_NETWORK_INTERFACE_INFO` constant with no response decoder, and `Smb2SessionSetupRequest.setSessionBinding()`, which encodes the binding flag correctly but is called only from unit tests. A session is pinned to one transport. |
| Compression | Not implemented | No context, no transform header, no LZ77/LZNT1. |
| RDMA (SMB Direct) | Not implemented | Two unused read-channel constants. No RDMA transport and no dependency. |
| Witness protocol | Not implemented | Nothing in the source tree. |

## Configuration knobs referenced above

| Property | Default | Effect |
| --- | --- | --- |
| `jcifs.client.minVersion` | `SMB1` | Lowest dialect offered. |
| `jcifs.client.maxVersion` | `SMB311` | Highest dialect offered. |
| `jcifs.client.useSMB2Negotiation` | `false` | Skip the SMB1 multi-protocol bootstrap. |
| `jcifs.client.signingPreferred` | `false` | **Does not enable SMB2 signing** — see above. |
| `jcifs.client.signingEnforced` | `false` | Require signing. Use this one. |
| `jcifs.client.ipcSigningEnforced` | `true` | Require signing on IPC$. |
| `jcifs.client.requireSecureNegotiate` | `true` | Validate the negotiate exchange on tree connect. |
| `jcifs.client.encryptionEnabled` | `false` | Opt in to SMB3 encryption — see [Encryption](#encryption). |
| `jcifs.client.transaction_buf_size` | `65535` | Drives the read and write ceilings. 512 bytes are subtracted from it, giving an effective 65023. |
| `jcifs.client.ssnLimit` | `250` | Sessions per connection before a new connection is opened. |
| `jcifs.client.dfs.disabled` | `false` | Disable DFS referral resolution. |

Note the prefix: jcifs 3.0.0 renamed the configuration namespace from
`jcifs.smb.client.*` to `jcifs.client.*`. Old property names are silently ignored
and fall back to defaults.

## Keeping this document honest

Every "Supported" entry above was traced to a caller on a real send or receive
path, and every "Not functional" entry names the dead end that stops it. When
changing this file, apply the same test: an identifier existing in the source
tree is not support. Check who calls it.

The integration suite under `src/test/java/org/codelibs/jcifs/smb/it/` exercises
authentication, signing, encryption, dialect negotiation, DFS and symlink
behaviour against a containerised Samba and against a real Windows server in CI.
Prefer adding a case there over trusting a unit test that decodes its own
encoded output — that is precisely how the encryption defects went unnoticed.
