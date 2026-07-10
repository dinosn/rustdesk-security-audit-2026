# RustDesk Security Assessment — Client + Server

**Targets:** `rustdesk` client @ `137298e` (Rust ~142K + Dart ~71K LoC) · `rustdesk-server` @ `91fb928` (~3.4K LoC) · shared `hbb_common` (client `7e1c392` / server `83419b6`).
**Method:** RAPTOR loop-hunt — 4 looped rounds, 4-altitude traversal (whole-project → file → functionality → function), N=15 isolated generators/round, every candidate 3-way reconciled (Claude generator → Claude judge-from-raw → **OpenAI gpt-5.4 cross-vendor judge-from-raw**) → orchestrator whole-flow verification. Two findings **live-proven** on the lab.
**Scope:** RCE / auth-bypass / MITM / privilege-escalation prioritized; DoS deprioritized (listed separately).
**Local-only** — 0day, not disclosed externally.

---

## Executive summary

RustDesk's **server (`hbbs`/`hbbr`) and shared framing are hardened** — parameterized SQL, 256 KB frame-prealloc cap, uuid-ownership on established IDs, loopback-gated admin/config, authenticated+encrypted TCP rendezvous. Exposure is concentrated in two places:

1. **A rendezvous/relay secure-channel-bypass cluster** — the "encrypted" P2P session can be **downgraded to plaintext, hijacked, or injected into** by an on-path attacker, a malicious/compromised server, or (for the UDP path) a blind spoofer.
2. **A confirmed Critical on the client** — a **malicious host can write an arbitrary file to the controller's machine → RCE**, via file-transfer directory-traversal.

31 in-scope findings survived reconciliation. The plugin subsystem's bugs (incl. a macOS command-injection) are **not reachable in shipped builds** (feature-gated) and are quarantined.

### Headline findings
| ID | Finding | Severity | Verification |
|----|---------|----------|--------------|
| **F-C10** | Malicious host → file-transfer path traversal → **arbitrary write → RCE on controller** | **Critical** | 4-way (incl. OpenAI whole-flow) |
| **F-C01** | `RequestRelay.secure` cleartext flag → **encryption downgrade to plaintext** session | Critical/High | 3-way |
| **F-C02** | Unauthenticated **UDP rendezvous** → `ConfigureUpdate` **persistent client redirect** + address injection | Critical/High | 3-way |
| **F-C03** | `RegisterPk` same-IP `&&` guard → **persistent ID hijack / MITM** | High/Critical | **LIVE-PROVEN** |
| **F-C04** | Port-forward / RDP tunnel **strips E2E encryption** | High | 3-way |
| **F-C05** | `WsFramedStream` **Text-frame secretbox auth-bypass** | High | 3-way |

---

## Critical

### F-C10 — Malicious host → arbitrary file write → RCE on the controller (CWE-22)
**Flow (3 layers):** `flutter/lib/models/file_model.dart:592-597` (+`Entry.fromJson:1580`) → `src/client/io_loop.rs:602-605` → `libs/hbb_common/src/fs.rs:759-799`.
**Root cause:** the local download destination `to = PathUtil.join(localDir, from.name)` is built from the **remote host's directory-listing entry name**, copied verbatim with no `normalize()`. Rust wraps it as `DataSource::FilePath(PathBuf::from(&to))` with no validation. `fs.rs` validators (`validate_file_name_no_traversal`, `join_validated_path`) inspect only the trailing `name`, **never the `base`**; the single-file empty-name exemption (fs.rs:491-495) makes the join return `base` verbatim → `File::create(base)` resolves the embedded `..`.
**Attack:** a malicious/compromised host lists a file named `..\..\..\…\Startup\update.exe` (Windows) or `../../../.ssh/authorized_keys` (Unix). When the victim downloads it (standard remote-file-manager action; file permission is default), the bytes land outside the download directory → **RCE on the controller**.
**Precondition:** victim initiates a download from the malicious host. **Remediation:** normalize + confine `to`/`base` to the chosen download root (reject `..`/absolute in `base`, not just `name`); canonicalize before `File::create`.

---

## High — secure-channel-bypass cluster (rendezvous/relay)

### F-C01 — Encryption downgrade to plaintext via cleartext `secure` flag
`server.rs::create_tcp_connection` (196-255) gates its entire encrypt handshake on a `secure` bool derived from the **cleartext** `RequestRelay.secure` field; and the controller does **not** `bail!` when the peer replies with a non-`PublicKey` message (244-246) — it proceeds to `Connection::start` in plaintext. A malicious server or on-path attacker flips `secure→false` (or strips the rendezvous-signed pk) → **both endpoints run plaintext** → the relay/path reads and injects keystrokes/screen/files. Gated only by the user "insecure" warning. **Remediation:** integrity-protect the security-mode negotiation; refuse plaintext when a verified server pk is configured; make the insecure indicator un-dismissable.

### F-C02 — Unauthenticated UDP rendezvous → persistent client redirect
`rendezvous_mediator.rs::start_udp` (214-271) receives on an **unconnected** UDP socket (`new_udp_for`) and `handle_resp` never checks the datagram source; the UDP rendezvous path has **no KeyExchange/signature** (unlike the TCP path, `secure_tcp_impl`). Any host that can deliver a datagram to the client's rendezvous socket injects server→client messages — `ConfigureUpdate` **persists attacker rendezvous-servers + `restart()`** (407-417), or `PunchHole`/`RequestRelay` inject attacker addresses. **Remediation:** authenticate UDP rendezvous messages (sign/KeyExchange as on TCP) or bind/verify the source; never persist config from an unauthenticated message.

### F-C03 — `RegisterPk` pk-substitution → persistent ID hijack (LIVE-PROVEN)
`rendezvous_server.rs:359-386`: for an existing peer with matching uuid, rejection fires only when **both** IP and pk changed (`&&`). A **same-source-IP** attacker who knows the uuid overwrites the server-pinned pk. The uuid "secret" = `hbb_common::get_uuid()` = raw **`machine_uid`** (non-secret) **transmitted in cleartext** in the RegisterPk UDP packet → an on-path attacker sniffs it. **Live-proven** on lab hbbs (`poc/poc_rendezvous.py`): same-IP+same-uuid overwrote the pk; wrong-uuid control was rejected. → future controllers receive the attacker's server-signed pk → **MITM/impersonation**. **Remediation:** require proof-of-possession (sign a challenge with the registered pk) before pk change; reject pk-change from a differing key regardless of IP.

### F-C04 — Port-forward / RDP tunnel strips E2E encryption
`tcp.rs::set_raw` drops the secretbox key; `port_forward.rs` + `connection.rs::try_port_forward_loop` call it on the network-facing peer link → **tunneled port-forward/RDP traffic is plaintext** on the (direct or relay) network. **Remediation:** keep the secretbox layer for tunneled data, or document/enforce that port-forward requires the transport's own encryption.

### F-C05 — WebSocket Text-frame secretbox authentication bypass
`websocket.rs::next` (290-303) authenticate-decrypts `Binary` frames but returns `Text` frames' **raw bytes with no decryption/auth**. In an encrypted WS session, an on-path attacker / malicious relay injects forged protocol messages via Text frames. **Remediation:** reject Text frames on the encrypted channel (or route them through `key.dec`). (Companion lead: `webrtc.rs::set_key` is a no-op — verify WebRTC-transported sessions apply the secretbox at all.)

---

## High — client / server (other)

- **F-R2-02** — `remove_jobs` id-confusion: a malicious **host overwrites a pending file on the controller** (path/authz).
- **F-R2-03** — **Cliprdr permission-bypass**: inbound clipboard-file messages processed without the clipboard/file permission gate.
- **F-R2-04** — **Windows main IPC** authorizes cross-session elevated peers → **local privilege escalation** (companion: portable-service shmem ACL never re-hardened).
- **F-R2-05** / **F-R4-01** — permission re-auth gaps: switch-sides bypasses `OPTION_ENABLE_TUNNEL`; Android mouse/key input injected **without keyboard permission**.
- **F-R2-07** — **Updater: downloaded artifact never signature/hash-verified**; update `url` from the unauthenticated version-check → **malicious/compromised (custom/self-hosted) API server or TLS-MITM → RCE**.
- **F-R3-01** — `custom_server.rs` accepts an **unsigned JSON config first** (signature check bypassable) → config-import redirect to attacker host/api/relay/key.
- **F-R3-02** — `proxy.rs` **CRLF/header injection** into the proxy `CONNECT` via unsanitized (server-supplied) `relay_server` → request smuggling/SSRF (needs configured HTTP/S proxy).
- **F-R4-02/03** — client trusts server-supplied addresses (`PunchHole`/`RequestRelay`/`FetchLocalAddr`) and peer-supplied port-forward targets → **SSRF / arbitrary internal-network connect** (F-C02 family).
- **F-S04** — unauthenticated **UDP reflector** via forged `AddrMangle` (**LIVE-PROVEN**; reflection/DoS-class).

## Medium (selected)
X-Real-IP/X-Forwarded-For spoofing (no trusted-proxy gate); `RegisterPk` TOFU ID-squatting; TLS `danger_accept_invalid_cert` fallback cached; permanent password hashed single-round SHA-256; at-rest secrets keyed by non-secret `machine_uid`; **2FA "Trusted Devices" bypass** via self-reported hwid; 2FA re-verify skipped on switch-sides/session-recency; **privacy-mode bypass cluster** (one-shot client-cooperative enforcement; `switch()` drops protection; host clipboard synced during privacy mode); non-ASCII keyboard path writes host clipboard without permission; `AudioFormat/AudioFrame` played without audio permission; `ToggleVirtualDisplay`/`turn_off_privacy` missing per-permission checks; login-failure lockout per-source-IP only; low-entropy one-time password.

## GATED — real bugs NOT in shipped builds
- **Plugin subsystem** (macOS `do shell script` **command-injection** [would be Critical], Zip-Slip `do_install_file`, unsigned `dlopen`, plugin-id, Windows `ShellExecuteW`): **`plugin_framework` is not a default feature and never enabled in `build.py`**, and `get_plugin_source_list()` returns `vec![]` (no remote catalog). Reachable only in a custom build that enables the feature **and** adds a plugin source.
- **WebRTC transport (F-R5-WEBRTC) — latent MITM design flaw:** `webrtc.rs::is_secured()` hardcodes `true` and `set_key()` is a no-op (discards the RustDesk secretbox); the DTLS fingerprint is used only as a cache key, **never pinned to the peer's verified Ed25519 pk**. Result: the insecure-connection consent prompt is skipped and the session is shown as "secured." **Not reachable today** (`webrtc` feature off + no rendezvous SDP wiring; only a dev demo). **Becomes a silent full-session MITM the moment WebRTC is wired to rendezvous signaling** — fix `is_secured()`/`set_key()` to pin the fingerprint to the peer pk **before** shipping the feature.

## Solid by design (checked, sound)
Server SQL (sqlx bound params); frame codec 256 KB prealloc cap (no alloc-bomb / no `bytes` reserve-overflow); `RegisterPk` uuid-ownership for **established** IDs; loopback-gated admin `check_cmd` + `ConfigureUpdate`; no server-side SSRF via `HttpProxyRequest`; **TCP** rendezvous authenticated+encrypted when a key is configured; codec `GoogleImage::to` sizing is `usize`=64-bit (**no** OOB overflow on shipped platforms — a "Critical" candidate refuted here); Rust file-transfer validates `..`+absolute on entry **names** (the F-C10 gap is specifically the *base* path).

## Deprioritized (DoS — out of primary scope, logged)
`online_request` unbounded loop; `PUNCH_REQS`/`PeerMap` growth; `compress::decompress` zstd bomb; AV1 unbounded dimensions; codec `chroma()` type-confusion (Low mem); KCP garbage-datagram task spawn; whiteboard thread spawn; protobuf recursion (dep).

---

## Coverage (completeness gate)
Full component inventory in `INVENTORY.md` (~60 components, A–M). **Covered across R1–R4:** all A (hbb_common), B (server), C (connection/services), D (session), E (crypto/rendezvous), F (IPC), G (HTTP client — light), H (plugin, gated), I (updater), J (platform), K (codec/clipboard/drivers), L (Dart/FFI), M (misc). **Explicitly omitted:** `src/lang/*` (i18n data), `libxdo-sys-stub` (trivial), transitive-dep CVEs (deterministic SCA in `sca-*.json`, excluded from LLM scope). **Lighter coverage (candidates for a deeper pass):** `scrap` capture backends (K2), UI widgets (M2), WebRTC transport internals (verify the `set_key` no-op lead), a deeper codec fuzzing campaign.

## Verification artifacts (in `out/projects/rustdesk/`)
`FINDINGS.md` (full ledger) · `TRIED.md` (attempt ledger, 4 rounds + method learnings) · `r{1,2,3,4}_reconciled.json` (3-way verdicts) · `poc/poc_rendezvous.py` + `poc/RESULTS.md` (live proofs) · `sca-*.json` (dependency CVEs).

## Top remediation priorities
1. **F-C10** — confine the download destination to the chosen root (reject `..`/absolute in `base`).
2. **F-C01/C02** — authenticate the rendezvous channel end-to-end (esp. UDP); refuse silent plaintext downgrade; un-dismissable insecure indicator.
3. **F-C03** — proof-of-possession before pk change; don't trust cleartext `machine_uid` as an ownership secret.
4. **F-R2-07** — sign/verify update artifacts (don't rely on TLS alone), esp. for custom/self-hosted API servers.
5. **F-C04/C05** — no transport may carry session data outside the secretbox.
