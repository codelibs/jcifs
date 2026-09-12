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
| QUERY_DIRECTORY | Supported | Streaming enumeration. A listing cut short by a failure reports it rather than ending quietly — see [Reconnecting after a dropped connection](#reconnecting-after-a-dropped-connection). |
| CHANGE_NOTIFY | Supported | Via `SmbResource.watch(int, boolean)`. Blocking; `SmbWatchHandle.cancel()` ends a pending call. |
| IOCTL | Partial | Reachable FSCTLs: DFS_GET_REFERRALS, PIPE_PEEK, PIPE_TRANSCEIVE, SRV_COPYCHUNK(_WRITE), SRV_REQUEST_RESUME_KEY, VALIDATE_NEGOTIATE_INFO. The other defined FSCTL constants are never sent. |
| Async / `STATUS_PENDING` interim responses | Supported | |
| FLUSH | Supported | Sent by `SmbFileOutputStream.flush()`. Every write goes out as it is made, so there is no local buffer to push; what `flush()` contributes is the durability barrier, asking the server to commit what it has taken. Before 3.0.4 the method was the inherited no-op from `OutputStream`, so a caller that flushed and saw no error had no way to tell the data was still only in the server's cache. Nothing is sent on SMB1, which has no equivalent request. |
| LOCK | Supported | Sent by `SmbRandomAccess.lock()`, `tryLock()` and `unlock()`, which a caller reaches through `SmbResource.openRandomAccess()`. `tryLock` sets `SMB2_LOCKFLAG_FAIL_IMMEDIATELY` and reports a range another open holds as `false` rather than raising: Samba answers such a request `STATUS_LOCK_NOT_GRANTED`, and a server answering `STATUS_FILE_LOCK_CONFLICT` instead is read the same way. An unlock has to name the range that was locked, because a server matches it against the ranges it recorded rather than against overlapping bytes. SMB2 only: SMB1 has LOCKING_ANDX, but this client builds it solely to decode an inbound oplock break and has no outbound lock path, so a lock over SMB1 is refused rather than silently skipped. A lock belongs to the open that took it and does not survive a reconnect; see [Why durable handles are not planned](#why-durable-handles-are-not-planned). |
| ECHO | Not functional | `Smb2EchoRequest` exists and is referenced nowhere. There is no keepalive or liveness probe. |
| CANCEL | Supported | Sent by `SmbWatchHandle.cancel()`, which is the only caller: CHANGE_NOTIFY is the one request the API blocks in. The cancelled `watch()` returns `null` rather than a set of changes, and the open survives, so the directory can be watched again. Closing the handle also ends a pending watch, but as a side effect of closing the open, and what the server then answers the notify with is up to it — Samba sends STATUS_NOTIFY_CLEANUP and an empty set. Actually sending one required fixing the header encoder: it chose between the async and sync header layouts from a field only ever set while decoding, so a cancel whose flags said async still carried a tree id where the server reads the AsyncId, and was discarded. |
| OPLOCK_BREAK | Partially supported | Breaks are decoded and acknowledged; nothing requests an oplock, so none arrive by default. See below. |

## Caching, oplocks and handles

Oplock breaks are handled; everything else here is absent. Note what the first
row means for the rest: nothing asks for an oplock or a lease, so on a
conforming server none of the break handling below is reached in ordinary use.
It matters for a caller that requests one itself, and for a server that sends a
break anyway.

| Feature | Status | Notes |
| --- | --- | --- |
| Oplock request on CREATE | Not functional | `setRequestedOplockLevel()` has no production caller, so **every CREATE still requests oplock level NONE**. A conforming server therefore never breaks an oplock of ours (MS-SMB2 3.3.5.9), which is why the break handling below is inert in normal use. |
| Granted oplock level | Supported | Decoded and recorded on the open, which is what decides whether a later break of it has to be acknowledged. |
| Oplock break notification | Supported | Decoded and resolved to the open it names. Since the notification carries TreeId 0 and, on several servers, SessionId 0, the open is found by file id in the session open tables rather than from the header. A break naming an open the client does not have is ignored, as MS-SMB2 3.2.5.19.1 requires. jcifs caches nothing, so there is no cached data to discard. |
| Oplock break acknowledgement | Supported | `Smb2OplockBreakAcknowledgment` is sent on the broken open's own tree, which is what gives it the session and tree id the server requires. A break from level II to none is not answered at all (MS-SMB2 2.2.24.1). The acknowledgement is sent off the receive thread, because it draws a reply and waiting for one there would stop the loop that reads it. |
| SMB3 leases | Not implemented | Two unused constants; no lease is ever requested, and there is no lease create context to request one with. A lease break is now decoded rather than fatal: before 3.0.4 its 44-byte body failed a decode that demanded 24, and that failure closed the socket, logged off every session and failed every request in flight on the connection. Such a break is logged and otherwise ignored, since no lease was ever held — there is no lease break acknowledgement message either. A lease holding `SMB2_LEASE_HANDLE_CACHING` is one of the two ways to qualify for a durable handle; see [Why durable handles are not planned](#why-durable-handles-are-not-planned). |
| Directory leasing | Not implemented | Unused capability constant; depends on leases. Worth knowing before planning anything on it: a directory lease may only be `R` or `R|H` (MS-SMB2 3.3.5.9.11 strips write caching for directories), and Samba 4.21 does not implement directory leases at all, so nothing is granted there whatever the client asks for. |
| Durable / persistent handles | Not implemented, and not planned | No DHnQ/DH2Q/DHnC/DH2C contexts, no app instance id, no handle reconnect path. See [Why durable handles are not planned](#why-durable-handles-are-not-planned) for what it would take and why it is not worth it here. |
| Create contexts (the framework itself) | Not functional | The request side encodes correctly: `Smb2CreateRequest.setCreateContexts()` lays contexts out as MS-SMB2 2.2.13.2 requires, and `CreateContextIT` checks that a real server answers each one. But nothing outside the tests calls it, and `Smb2CreateResponse.createContext()` is `return null`, so a context in a response is skipped. Before 3.0.4 no context could be sent at all — `size()` left out each context's header and name, so the request failed before it was sent — and the encoder also zeroed every `Next` and undercounted `CreateContextsLength`. |

The last row is the blocker for the three above it: leases, durable handles and
persistent handles all ride on create contexts. Contexts can now be sent, but a
context in a response is still dropped. Note how little is missing there: the
walker in `Smb2CreateResponse` is complete — it follows the `Next` chain,
bounds-checks each entry and collects them — and only the factory that turns a
context name into a response object is `return null`. Recognising a lease or
durable handle response means adding those response types and a dispatch on the
name, not writing a decoder.

### Why durable handles are not planned

A durable handle survives a dropped connection: the server keeps the open alive
and the client reclaims it rather than reopening by path. This records why it is
not planned, so the question does not have to be researched again.

**The precondition is not batch oplocks alone.** MS-SMB2 3.3.5.9.6 requires
either a batch oplock *or* a lease whose state includes
`SMB2_LEASE_HANDLE_CACHING`. The v2 contexts say the same, in Appendix A's note
on 3.3.5.9.10, in 3.3.7.1, and in both reconnect handlers, as do Samba — which
tests the *granted* lease type in `source3/smbd/smb2_create.c` — and ksmbd. The
Linux client has used the lease form by default since 2013. A request made with
neither is **silently ignored**: the create succeeds and the response context is
simply absent, so refusal has to be detected by that absence rather than by a
status code.

**The least disruptive qualifying state is a lease of `R|H`.** It is not broken
by another client's open at all, read or write. It breaks only when that open
would otherwise fail with `STATUS_SHARING_VIOLATION`, and only then does the
other client wait — for one round trip, now that breaks are acknowledged. A
batch oplock is broken by *every* conflicting open and makes the opener wait
each time, and it is broken even when the same client reopens the same file,
because only a lease carries a client-chosen key that exempts its holder. `R` is
required: a lease asking for handle caching alone is reduced to none.

**Directories cannot have one.** MS-SMB2 3.3.5.9.10 skips durability when the
open is a directory, and Samba 4.21 blocks it twice over — its durable cookie is
refused for directories, and it has no directory leases to qualify with. Since
directory enumeration is much of what this library does, the feature would not
apply to it.

**What it buys is mostly not what this client uses.** A durable handle preserves
byte-range locks across the reconnect — the reason the Linux client implemented
it — along with share-mode semantics and handle identity across a rename. For
reads and writes there is nothing to resume: SMB2 carries explicit offsets, so
reopening by path and continuing at the recorded offset loses none of it, which
is what the streams already do. See
[Reconnecting after a dropped connection](#reconnecting-after-a-dropped-connection).

Byte-range locks are the exception, now that `SmbRandomAccess` can take them. A
lock belongs to the open that took it, and a dropped connection is recovered by
reopening the path, which gives a new open holding no locks — so a lock taken
before the drop is gone afterwards and nothing replays it. That is a caveat for
callers who lock rather than an argument for durable handles, since what rules
those out still holds: the batch oplock or `R|H` lease that a durable open has to
qualify with cannot be requested at all today.

**And it is least reliable exactly when it would be wanted.** If another client
opens the file while the connection is down, the server closes the durable open
rather than keeping it (3.3.4.6 and 3.3.4.7), and a lease broken below handle
caching makes the reconnect fail outright. The handle also expires on its own,
typically within 60 to 180 seconds.

One caveat on the evidence: that Windows grants a v2 durable handle for a lease
with no oplock is taken from Microsoft's documented product behaviour and its
protocol test suite, not from an observed exchange.

## Throughput and credits

| Aspect | Status | Notes |
| --- | --- | --- |
| Maximum read size | **1048576 bytes** on SMB 2.1 and later, **64936** on SMB 2.0.2 | The smaller of `jcifs.client.maxTransferSize` and what the server offers. |
| Maximum write size | **1048576 bytes** on SMB 2.1 and later, **64904** on SMB 2.0.2 | As above. |
| `SMB2_GLOBAL_CAP_LARGE_MTU` | Supported | Advertised whenever the configured dialect ceiling reaches SMB 2.1, and negotiated when the server also offers it. The transfer sizes hang off this capability rather than off the size the server advertises, because a server offers a large size either way: Samba 4.21 offers 8 MiB for read, write and transact even to a client that never asked for multi-credit, and using it without the capability would spend credits the connection never had. |
| `creditCharge` on outgoing requests | Supported | A read or write charges one credit per 64 KiB it spans (MS-SMB2 3.2.4.1.2), counting the payload it sends for a write and the payload it expects back for a read. The charge is only put on the wire once multi-credit is negotiated - the field is reserved before SMB 2.1 - and a request consumes that many message ids (MS-SMB2 3.2.4.1.3), not one. |
| Credit accounting | Supported | Per connection. |
| Connection pooling | Supported | See below. |

The read and write ceilings follow from `jcifs.client.maxTransferSize` (default
1 MiB) and the size the server offers, whichever is smaller. Reads and writes are
chunked at exactly that size, so a transfer costs one round trip per megabyte
rather than one per 64 KiB.

Two things this deliberately does not do. It does not raise
`jcifs.client.rcv_buf_size` or `snd_buf_size`, which are shared with SMB1: the
SMB1 receive path refuses anything above `0xFFFF`, so raising them would make
SMB1 issue reads whose responses it then rejects. And it does not move the
transfer size on SMB 2.0.2, which has no multi-credit at all — there the old
`jcifs.client.transaction_buf_size` arithmetic still applies, unchanged.

### Multiple connections to one server

There is no SMB3 multi-channel (see below), but the transport pool will open
additional TCP connections to the same host once a connection reaches
`jcifs.client.ssnLimit` sessions (default **250**). Lowering that value spreads
sessions across more connections; `ssnLimit=1` gives one connection per session.
These are independent connections, not bound channels of one session.

### Reconnecting after a dropped connection

There are no durable handles, so a dropped connection invalidates every open
handle. A stream notices on its next operation, reopens the file by path, and
carries on writing or reading at the position it had reached.

A write stream keeps what it has already written. Before 3.0.4 the reopen used
the create flags the stream was constructed with, so on SMB2 it came back with
`FILE_OVERWRITE_IF`: the file was truncated and the stream wrote on at its old
offset, leaving everything before that offset as a hole. Nothing reported it —
the write returned normally and `close()` succeeded.

A directory listing has nothing to reopen: the open handle *is* the enumeration.
Since 3.0.4 a listing that cannot be continued reports that. `children()` hands
out the entries it had already read and then throws `RuntimeCIFSException` from
the iterator; `list()`, `listFiles()`, `SmbFile.delete()` and `copyTo()` throw
`SmbException`. Before that the listing simply ended, which a caller cannot tell
apart from a directory that holds only those entries.

SMB1 workgroup and server browsing is a separate code path that had the same
problem, and since 3.0.4 it keeps the same contract: a browse cut short by a
failure hands out the servers already read and then throws
`RuntimeCIFSException`, instead of ending as though the workgroup held only
those.

A random access file no longer brings back a file that has gone. It is opened
once and reopened by path whenever its handle is no longer valid, replaying the
flags exactly as they stand — and `O_CREAT` was among them, for mode `r` as well
as `rw`. So before 3.0.4 a reopen after a dropped connection resurrected a file
deleted in the meantime as an empty one, and `openRandomAccess("r")` on a path
that never existed created it rather than failing. Mode `rw` still creates the
file on its first open, as it always has.

## Other features

| Feature | Status | Notes |
| --- | --- | --- |
| DFS referral resolution | Supported | On by default (`jcifs.client.dfs.disabled=false`). Uses `FSCTL_DFS_GET_REFERRALS`; the `_EX` variant is not used. |
| Server-side copy (copychunk) | Partial | `SmbFile.copyTo` uses `FSCTL_SRV_COPYCHUNK` **only when source and destination resolve to the same tree connection**. Cross-share and cross-server copies silently fall back to read/write streaming. |
| Named pipes | Supported | Transceive and peek. |
| Symbolic links / reparse points | Partial | A path that crosses a symbolic link fails with `SmbSymlinkException`, which carries the target decoded from the `STATUS_STOPPED_ON_SYMLINK` error response: `getSubstituteName()`, `getPrintName()`, `isRelative()` and `getUnparsedPathLength()`. Links are **not followed** — there is no resolution or retry, so a caller that wants to traverse one has to act on the target itself. Which server you are talking to decides whether this comes up at all: Samba resolves a link that stays inside the share and never reports one, so the error surfaces mainly against Windows. |
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
| `jcifs.client.maxTransferSize` | `1048576` | Largest payload a single SMB2 read or write may carry. The negotiated size is the smaller of this and the server's offer. Has no effect below SMB 2.1, which cannot carry more than 64 KiB in one request. |
| `jcifs.client.transaction_buf_size` | `65535` | Drives the transact size, and the read and write ceilings on SMB 2.0.2 and SMB1. 512 bytes are subtracted from it, giving an effective 65023. |
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
