# RustDesk Loop-Hunt — Confirmed / Tracked Findings (FINDINGS.md)

Exclusion set for the loop. Every survivor gets exactly one disposition:
**confirmed** | **needs-live-validation** | **corrected** | **rejected**.

Finding contract (enforced by hand): root cause (function+file+missing check) · trace from
attacker-controlled entry point → dangerous sink · concrete attack (attacker, exact input,
observed result) · severity = likelihood × impact · confidence + reason. Two-axis
(confirmed vs potential) severity when a deciding layer is unobserved.

---

## CONFIRMED
_Dual-confirmed = independent Claude read (orchestrator) + OpenAI gpt-5.4 cross-vendor judge both agree._

### ★ F-C10 — MARQUEE: malicious HOST → arbitrary file write → RCE on the CONTROLLER (file-transfer path traversal, CWE-22)
- **Components (whole-flow, 3 layers):** `flutter/lib/models/file_model.dart:592-597` + `Entry.fromJson:1580-1585` → `src/client/io_loop.rs:602-605` → `libs/hbb_common/src/fs.rs` (`validate_file_name_no_traversal:460`, `join_validated_path:556`, `write:759-799`).
- **Root cause:** the download destination `to = PathUtil.join(localDir, from.name)` is built from the **remote peer's directory-listing `Entry.name`** copied verbatim (no `normalize()`); `io_loop.rs` wraps it as `DataSource::FilePath(PathBuf::from(&to))` with **no validation**; `fs.rs` validators inspect only the trailing `name`, **never `base`**, and the single-file empty-name exemption (fs.rs:491-495, `validate_no_symlink_components` early-returns on empty name) makes `join_validated_path` return `base` verbatim → `File::create(base)` resolves embedded `..`.
- **Attack:** a malicious/compromised host (or MITM, via F-C01/C02 downgrade) lists a file named `..\..\..\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\update.exe` (Win) or `../../../.ssh/authorized_keys` (Unix); when the victim downloads it (or bulk-downloads the folder), attacker bytes are written outside the download dir → **RCE on the controller** (autostart / authorized_keys / .bashrc).
- **Verification:** Claude gen **Critical** + Claude judge **confirmed/Critical** + my full cross-layer read + **OpenAI whole-flow judge confirmed/Critical**. (OpenAI's initial per-file reject was file-read/cross-layer blindness — resolved by re-judging with all 3 files.)
- **Severity:** **Critical** (arbitrary-write→RCE) with precondition: victim initiates a download from the malicious host (standard remote-file-manager UX; file-transfer permission is default). **Disposition: confirmed; live-validation recommended** (client build + malicious host serving crafted listing — heavy; static cross-layer proof is complete).
- **Method note:** cross-layer/FFI findings MUST be judged with the whole flow, not per-file — per-file judges false-negative on base-taint from another file.

### F-S02 — register_pk trust-on-first-use (TOFU) ID squatting → impersonation/MITM enabler
- **Component:** server `rendezvous_server.rs` `handle_udp` RegisterPk (lines 342-419) + `peer.rs` `update_pk`
- **Root cause:** `handle_udp` binds `id → attacker uuid/pk` for any *unclaimed* id (`peer.uuid.is_empty()` ⇒ `changed=true`, lines 356-358) with no proof-of-possession or reservation. Existing ids are protected by uuid-ownership (359-386); unclaimed ones are first-writer-wins.
- **Trace:** attacker → `RegisterPk{id=victim, uuid, pk}` over UDP → `pm.get_or` creates entry → `update_pk` persists attacker pk → later a controller connecting to `id` gets attacker pk in PunchHoleResponse/LocalAddr via `get_pk` (623-627, 657-660).
- **Attack:** attacker pre-claims a target id that has never registered (or whose server record was lost); server serves the attacker's public key to controllers → attacker can impersonate / MITM that id.
- **Severity:** Medium (confirmed) / **potential High** (session MITM if combined with routing). **Disposition: confirmed.** In-scope (auth-weakness / MITM enabler).
- **Note:** partly by-design for self-hosted TOFU ID servers; still a real pre-registration weakness. Comparable: any TOFU identity system (SSH first-connect).

### F-S01 — X-Real-IP / X-Forwarded-For spoofing from any WebSocket client
- **Component:** server `rendezvous_server.rs` `handle_listener_inner` ws callback (lines 1154-1166)
- **Root cause:** ws handshake callback overwrites the peer `addr` from client-supplied `X-Real-IP`/`X-Forwarded-For` with no check that the TCP peer is a trusted reverse proxy/loopback → any WS client spoofs its source IP.
- **Trace:** attacker → WS connect on ws_port with `X-Real-IP: <chosen>` → `addr` overwritten → used by `is_lan`/`same_intranet` routing (728-745), relay selection (730), audit `from_ip` (711-725), `RequestRelay` socket_addr (500).
- **Attack:** spoof LAN membership (`is_lan` true → internal `local_ip` relay disclosure), forge punch-request audit logs, influence routing.
- **Severity:** Medium. **Disposition: confirmed.** (Legit when behind a trusted proxy, but there's no trusted-proxy gate, so it's unconditional.)

### F-S03 — handle_online_request unbounded peers loop (DoS)
- **Component:** server `rendezvous_server.rs` `handle_online_request` (line 790)
- **Root cause:** allocates + per-peer locked loop sized from attacker `OnlineRequest.peers` with no cap.
- **Severity:** Low (DoS). **Disposition: confirmed but DEPRIORITIZED** — pure-DoS, out of primary scope (RCE/auth-bypass/MITM). Logged, not featured.

### F-C02 — Unauthenticated UDP rendezvous channel → server-message injection (persistent client redirect)
- **Components:** client `rendezvous_mediator.rs` `start_udp` (214-271) + `handle_resp` `ConfigureUpdate` arm (407-417); `socket_client.rs` `new_udp_for` (227-241); `common.rs` `secure_tcp_impl` (1938+).
- **Root cause:** the UDP rendezvous socket is **unconnected** (`new_udp_for` → `new_udp`, receives from any source) and `handle_resp` never checks the datagram source against the configured server; the **UDP** rendezvous path has **no KeyExchange/signature** (unlike TCP `secure_tcp_impl`, which requires+verifies the server key). So any host that can deliver a UDP datagram to the client's rendezvous socket injects arbitrary server→client messages.
- **Trace:** attacker UDP datagram → `start_udp` `socket.next()` (267) → `handle_resp` (271) → `ConfigureUpdate` arm persists `cu.rendezvous_servers` via `Config::set_option` + `Config::set_serial` + `restart()` (409-415) ⇒ client permanently switches to attacker-controlled rendezvous servers. Same path also injects `PunchHole`/`RequestRelay` (attacker peer addresses).
- **Attacker:** on-path (rogue WiFi/gateway/ISP) or, for public-IP/full-cone-NAT clients, off-path host reaching the UDP port; can spoof the server source IP (UDP, no handshake).
- **Verification:** Claude gen+judge **Critical**; OpenAI **Critical/High**; my independent read confirmed (unconnected socket + no source check + UDP path unauthenticated).
- **Severity:** **High** (confirmed) / **potential Critical** (persistent MITM redirect). **Disposition: confirmed** (delivery reachability = needs-live-validation on NAT). TCP rendezvous is SAFE (authenticated when key present).

### F-C03 — RegisterPk pk-substitution via weak `&&` guard → on-path persistent ID hijack (MITM)
- **Component:** server `rendezvous_server.rs` `handle_udp` RegisterPk arm (line 359-386) → `peer.rs::update_pk` (418).
- **Root cause:** for an existing peer with matching uuid, the mismatch rejection fires only when **both** `peer.info.ip != ip` **and** `peer.pk != rk.pk` (line 360). A same-source-IP packet with a *different pk* is therefore accepted and overwrites the server-pinned public key.
- **Why the uuid barrier fails:** the "ownership" uuid = `hbb_common::get_uuid()` = raw **`machine_uid`** (`/etc/machine-id`, Windows MachineGuid, macOS IOPlatformUUID) — non-secret, and **transmitted in cleartext in the RegisterPk UDP packet**. An on-path attacker sniffs `{id, uuid}`, then sends a source-IP-spoofed `RegisterPk{id, uuid, pk=attacker}` → server overwrites pk.
- **Trace:** on-path sniff of victim RegisterPk → attacker RegisterPk (same id/uuid, same IP, attacker pk) → guard bypassed (ip unchanged) → `update_pk` → `get_pk` now signs+serves attacker pk in every future PunchHoleResponse/RelayResponse for that id → attacker MITMs/impersonates the device to all future controllers.
- **Verification:** Claude **Critical**; OpenAI **Critical**; **my initial Medium was a FALSE NEGATIVE** — I wrongly treated uuid as a secret; corrected up after seeing it is sniffable on the wire. (Methodology note: exactly the FN cross-vendor judging exists to catch.)
- **Severity:** **High / potential Critical** (on-path → persistent ID hijack). **Disposition: CONFIRMED — LIVE-PROVEN on lab hbbs** (`poc/poc_rendezvous.py`): legit pk 0x11→ attacker same-IP same-uuid → pk overwritten to 0xAA; wrong-uuid control rejected (pk unchanged). Server mechanic definitively proven; full remote adds on-path uuid-sniff + source-IP spoof.

### F-C05 — WsFramedStream Text-frame secretbox authentication bypass
- **Component:** `hbb_common/websocket.rs` `WsFramedStream::next` (290-303).
- **Root cause:** `Binary` frames are authenticate-decrypted with `key.dec()` (293-297) but `Text` frames are returned as **raw bytes with no decryption/auth** (300-302). In an encrypted WS session, forged protocol messages wrapped in Text frames bypass the secretbox MAC.
- **Trace:** attacker (on-path / malicious relay / peer) sends a WS `Text` frame carrying a crafted `Message` protobuf → `next()` returns raw bytes → caller parses+acts on an **unauthenticated** message inside an otherwise-encrypted session (input/clipboard/file/permission messages).
- **Verification:** Claude **High**; OpenAI **High (confirmed)**; my read confirmed the Text/Binary asymmetry.
- **Severity:** **High** (auth-bypass → unauthorized in-session control). **Disposition: confirmed** (requires WS transport in use; validate which message types the receiver acts on).

### F-S04 — Unauthenticated UDP reflector via forged AddrMangle destination (reflection)
- **Component:** server `rendezvous_server.rs` `handle_hole_sent` (615/634) + `handle_local_addr` (649) — `AddrMangle::decode` is unauthenticated reversible arithmetic (hbb_common/lib.rs).
- **Root cause:** the server sends a `PunchHoleResponse` to an attacker-chosen address decoded from `PunchHoleSent.socket_addr` with no auth/rate-limit → confused-deputy reflector.
- **Verification:** Claude **High**; OpenAI **High**; **LIVE-PROVEN on lab hbbs** (`poc/poc_rendezvous.py`): victim listener that never contacted hbbs received a reflected PunchHoleResponse. **Severity: High (reflection/DoS-class) — DEPRIORITIZED** per scope (no-DoS), logged.

### Tier-2 — both-vendor-confirmed Medium (in-scope, logged; not featured)
| ID | Finding | Class |
|----|---------|-------|
| F-S05 | Unauth `RegisterPeer` lets a same-IP/NAT-sharing attacker silently take over addr mapping | spoofing |
| F-S06 | `relay_server` field (PunchHole/FetchLocalAddr/RequestRelay) drives outbound connect → SSRF/pivot | ssrf |
| F-S07 | TLS `danger_accept_invalid_cert` fallback cached indefinitely → MITM after one accept | mitm-tls |
| F-C06 | Permanent password hashed with single unstretched SHA-256 (no KDF/salt-stretch) | crypto-weakness |
| F-C07 | At-rest secret encryption keyed by raw non-secret `machine_uid` (see F-C03) | crypto-weakness |
| F-C08 | Untrusted `control_permissions`/`controlled_context` rendezvous fields trusted by client | auth-bypass |
| F-S08 | Cross-session `RelayResponse` address injection by any TCP-registered client | spoofing |
| F-C09 | Default one-time password ~20-30 bits entropy (OpenAI escalated to High) → brute-force remote access — **check `login_failure_check` rate-limit in R2** | auth-weakness |
| F-S09 | Unauth admin/moderation command channel "gated only by source addr" — **R2: confirm not reachable via X-Fwd-For spoof** | auth-bypass |

## ROUND 2 — CLIENT RCE SURFACE (47 candidates → 3-way reconciled; plugin cluster gated)

### F-C04 — Port-forward/RDP tunnel strips E2E encryption (CONFIRMED, both vendors, shipped)
- `hbb_common/tcp.rs::set_raw` drops the secretbox key; `src/port_forward.rs` + `server/connection.rs::try_port_forward_loop` call it on the network-facing peer link → tunneled port-forward/RDP bytes traverse the (direct or relay) network in plaintext. Two independent R2 survivors + both vendors confirm. **High** (cleartext transmission of tunneled data; on-path/relay reads it). Resolves the R1 F-C04 open question in the vulnerable direction.

### F-R2-01 — `GoogleImage::to()` RGB buffer overflow — **REJECTED** (orchestrator static verification)
- Claimed 32-bit int-overflow in `rgb.h * bytes_per_row` (mod.rs:444) → OOB write on decode.
- **Refuted:** `GoogleImage::width()/height()` return **`usize`** (mod.rs:425-426); the sizing math (`get_bytes_per_row` + `resize`) is all `usize` = **64-bit** on shipped platforms → no overflow for any realistic frame size (8K ≈ 132 MB). Overflowing 64-bit usize needs ~2³² px/side, which libvpx/aom's own YUV-plane allocation OOMs on first (unreachable). 32-bit builds are the only theoretical exposure and are gated the same way.
- **Verdict:** Claude Critical / OpenAI High — **both over-rated**; the per-file judges saw the multiply but missed the `usize` operand type. **Disposition: rejected (non-issue on 64-bit).** No fuzz harness warranted for this lead. (Codec convert `usize` sizing → SOLID BY DESIGN on 64-bit.)

### F-R2-02 — `remove_jobs` id-confusion: malicious HOST overwrites a pending file on the CONTROLLER (path-traversal, High, both vendors)
- Controller-side: a malicious host reuses/confuses a job id so a file write lands on an attacker-chosen pending local path → arbitrary file overwrite on the controller. authz/path-confusion.

### F-R2-03 — Cliprdr (file-clipboard) permission-bypass cluster (authz-bypass, High, both vendors)
- Inbound Cliprdr (binary/file clipboard) messages are processed **without** re-checking the clipboard/file-transfer permission gate → a peer performs clipboard file operations it wasn't granted. (Two survivors: inbound cliprdr + the same missing gate poisoning state.) Plus two Cliprdr `FileContentsRequest` range int-overflows (Medium).

### F-R2-04 — Windows main IPC ("") authorizes cross-session elevated peers (privesc, High, both vendors)
- The Windows main IPC pipe authorizes cross-session peers, exposing elevated operations to a lower-privileged local session → **local privilege escalation**. Companion: portable-service shared-memory parent-dir ACL never re-hardened (High, needs-live); `authorize_windows_portable_service_ipc_connection` discards the exe check (needs-live).

### F-R2-05 — Switch-sides re-authorization bypasses `OPTION_ENABLE_TUNNEL` permission (authz-bypass, High, both vendors)
- The switch-sides (reverse control) re-auth path fails to re-enforce the tunnel permission → a peer gains port-forward/tunnel capability it wasn't granted.

### F-R2-06 — Symlink path-confusion arbitrary write in file transfer (arbitrary-write, High, both vendors — conditional)
- `fs.rs` validates symlinks on `base/name` but `write()`/`set_stream_offset()` operate on derived `.download`/`.digest` sibling paths that are **not** symlink-checked → arbitrary write if a symlink is pre-planted at the sibling path. **Precondition: attacker must pre-place the symlink** (needs a separate primitive) → High-conditional.

### F-R2-07 — Updater: downloaded artifact never signature/hash-verified (supply-chain, Medium→High in custom-server threat model)
- `updater.rs` writes the downloaded update binary to disk with **no code-signature/hash check**; the update `url` comes from the (unauthenticated) version-check response. Official channel relies solely on TLS; a **malicious/compromised API server (self-hosted/custom-server) or TLS-MITM → arbitrary update URL → unsigned download + run → RCE.** Content-Length-equality used in place of integrity (companion High).

### Tier-2 R2 (both-vendor Medium/notable, logged)
| ID | Finding | Class |
|----|---------|-------|
| F-R2-08 | AV1 decoder accepts unbounded frame dimensions → unchecked alloc/size (needs-live) | memory |
| F-R2-09 | Terminal `service_id` namespace has no peer-identity binding (OpenAI escalated to High) | authz-bypass |
| F-R2-10 | Update/terminal `reset_status` unauthorized; one-time-password throttle per-source-IP only (distributed brute-force) | authz/logic |
| F-R2-11 | vpx/aom `Image::chroma()` subsampling type-confusion → mis-sized reads (Low, memory) | type-confusion |
| F-R2-12 | `get_home()` username shell-interpolation — Low (needs non-standard identity backend; not remote) | command-inj |

### GATED — real bugs NOT in shipped builds (plugin_framework feature disabled + empty source list)
Verified: `get_plugin_source_list()` = `vec![]` (manager.rs:66, remote catalog commented out); `plugin_framework` absent from `default` features and never enabled in `build.py`. These require a **custom build enabling the feature AND adding a plugin source**:
- macOS `do shell script` command-injection (was Critical), Zip-Slip `do_install_file` arbitrary write, unsigned `dlopen` plugin load, plugin-id identity/containment, Windows `ShellExecuteW` unquoted plugin args, `PluginRequest` misc no-gate. **Disposition: gated / not-shipped** (report for custom-plugin builds only).

## ROUND 3 — BREADTH (remaining inventory: Dart logic, FFI, custom_server/proxy, services, privacy-mode, drivers)
34 candidates → 28 survivors → 28 OpenAI-judged (r3_reconciled.json). Yield declining (mostly Medium), severity down vs R1/R2.

### F-R3-CRIT (corrected) — file_model.dart `from.name` download path — mitigated at Rust layer, single-file gap
- Dart `sendFiles` (file_model.dart:596) joins the remote peer's `Entry.name` into the local download dest → Dart-only agent called it **Critical** (arbitrary write on controller).
- **Cross-layer correction (orchestrator):** Rust `fs.rs::validate_file_name_no_traversal` (460-488) rejects `..` **and** absolute paths (Unix `/`, Windows `C:`/`\`), applied via `validate_transfer_file_names`. **Multi-file transfers defended.** Possible gap: single-file empty-name transfer is exempt (fs.rs:491-495, "dest carried by metadata"). **Disposition: needs-live-validation (Medium/High)** — test single-file download with `../`/absolute metadata path. Per-file Dart judge couldn't see the Rust validator.

### R3 confirmed (both-vendor ≥High/notable Medium)
| ID | Finding | Sev | Class |
|----|---------|-----|-------|
| F-R3-01 | `custom_server.rs::get_custom_server_from_config_string` tries **unsigned `serde_json` first** → signature check bypassed; unsigned config sets host/key/api/relay to attacker (config-import redirect) | High | authz-bypass |
| F-R3-02 | `proxy.rs::make_request` **CRLF/header injection** into proxy `CONNECT` via unsanitized `relay_server` (from malicious/MITM server) → request smuggling/SSRF (needs configured HTTP/S proxy) | High | ssrf |
| F-R3-03 | `2FA "Trusted Devices"` bypass — `handle_login_request_without_validation` (connection.rs:2455) grants TOTP bypass on **self-reported hwid+id+name+platform**, no crypto proof (cf. F-C03 self-reported-identity pattern) | Med→High | authz-bypass |
| F-R3-04 | **Privacy-mode bypass cluster**: one-shot client-cooperative enforcement; `privacy_mode::switch()` drops active protection; host clipboard synced to controller during privacy mode | Med | privacy-bypass |
| F-R3-05 | Non-ASCII/Unicode keyboard input path writes host OS **clipboard without the clipboard permission** (×2) | Med | authz-bypass |
| F-R3-06 | `ToggleVirtualDisplay` / printer-driver-install (`current_exe()` path) / `main_create_shortcut` FFI — missing per-permission checks + unquoted-arg injection (mostly local/privesc) | Med | authz/privesc |
| F-R3-07 | Enter-key submit auto-authorizes Android CM under password-only approve mode (needs key-event delivery) | Med | authz-bypass |
| F-R3-08 | Predictable `/tmp/.Xauthority` for headless X11; unquoted username in root install.sh (Linux privesc, needs non-standard username/session) | Low→Med | privesc |

## ROUND 4 — VARIANT-HUNT (siblings of confirmed clusters; convergence round)
19 candidates → 16 survivors — **mostly SIBLINGS of known clusters** (validates coverage) + F-C10 marquee. Signals convergence.
| ID | Finding | Sev | Cluster |
|----|---------|-----|---------|
| **F-C10** | (above) malicious host → arbitrary write → RCE on controller | **Critical** | fs write-gap |
| F-R4-01 | Android mouse/touch **and** key-event input injection **without keyboard permission** (×2) | High | perm-gate |
| F-R4-02 | Client trusts server-supplied addresses in `PunchHole`/`RequestRelay`/`FetchLocalAddr` → connect to attacker addr (F-C02 sibling) | High | client-trusts-server |
| F-R4-03 | SSRF / arbitrary internal-network connect via unauth peer/server-supplied target (port_forward/socket_client) | High | client-trusts-server |
| F-R4-04 | Root CLI provisioning (`--password`/`--set-unlock-*`) local authz-bypass | High | local-privesc |
| F-R4-05 | `AudioFormat`/`AudioFrame` played on host speakers **without audio permission or voice-call accept** (checks only peer-controlled `disable_audio`, never `self.audio`/`voice_calling`) | Med | perm-gate |
| F-R4-06 | Switch-sides reconnection **skips TOTP 2FA re-verification**; 2FA re-prompt skipped by session-recency cache (F-R3-03 siblings) | Med | reauth-bypass |
| F-R4-07 | `ToggleVirtualDisplay` / `turn_off_privacy` no per-permission check; login-failure lockout per-source-IP only (distributed bypass) | Med/Low | perm-gate |

## ROUND 5 — CONVERGENCE / DRY-CHECK (11 candidates → 8 survivors; NO new shipped High/Critical)
Effectively DRY for new bug-classes. Survivors: all siblings of known clusters, gated, or Low.
- **F-R5-WEBRTC (GATED, latent design flaw — report to vendor):** `webrtc.rs::is_secured()` hardcodes `true` and `set_key()` is a no-op (discards the RustDesk secretbox), while the DTLS fingerprint is used only as a HashMap cache key — **never pinned to the peer's verified Ed25519 pk**. So `io_loop.rs:187-193` / `port_forward.rs:128-133` **skip the insecure-connection consent prompt** and mark the session "secured." **Not reachable today** (`webrtc` Cargo feature off by default + no rendezvous SDP-exchange wiring; only the dev demo uses it). Becomes a **silent full-session MITM the moment WebRTC is wired to rendezvous signaling** without first pinning the fingerprint to the peer pk. Both vendors confirm the code flaw; gated on the feature. **Fix before shipping WebRTC transport.**
- Siblings (logged, not new): Android/iOS input-injection (F-R4-01), CLI `--import-config` bypasses settings-lock/policy (F-R3-01 family), unauthenticated liveness probe on shared root service (F-R2-04 family), terminal `service_id` client-chosen (F-R4 family).
- Low/new: `PeerConfig::path()` forbidden-char regex omits `.`; first CLI flag → flexi_logger log path (unsanitized); Windows IPC identity by PID (PID-reuse race, needs-live).

## SOLID BY DESIGN (checked, sound — calibrates the findings list)
- **Server SQL (database.rs):** all queries use `sqlx::query!`/`query_as!` with bound `?` params — no injection.
- **Frame codec (bytes_codec.rs):** speculative prealloc capped at 256KB (`MAX_PREALLOCATED_PAYLOAD_LEN`); no amplification, no int-overflow, RUSTSEC `bytes` reserve-overflow not reachable.
- **register_pk for EXISTING ids:** uuid-ownership enforced (359/372) — cannot hijack a claimed id's pk without its secret uuid.
- **ConfigureUpdate / admin check_cmd:** loopback-gated (438, 1097) — not remotely reachable.
- **HttpProxyRequest:** no server-side handler in hbbs — server-SSRF-via-proxy refuted.

## NEEDS-LIVE-VALIDATION

### F-C01 — Encryption-downgrade MITM via cleartext `secure` flag (WHOLE-FLOW, R2 centerpiece)
- **Components:** `server.rs::create_tcp_connection` (196-255, host side), `create_relay_connection_` (314-337), `client.rs::secure_connection` (760-836, controller side), `common.rs` crypto (2004-2023), `confirm_insecure_connection` (client.rs:3825).
- **Root cause (candidate):** the host gates its entire encrypt handshake on a `secure` bool derived from the **cleartext** `RequestRelay.secure` field (proto rendezvous.proto:149) / punch flow; and on the controller side, `create_tcp_connection` does **not `bail!`** when the peer replies with a non-`PublicKey` message (server.rs:244-246) — it proceeds to `Connection::start` in plaintext. Client `secure_connection` similarly falls back to non-secure on empty/mismatched pk (773, 782-792, 816-820).
- **Trace (candidate):** MITM rendezvous server or on-path network attacker flips `secure→false` (or strips the rendezvous-signed `signed_id_pk`) → host skips SignedId/key setup → controller receives no valid SignedId → both proceed plaintext → attacker on the relay/path reads + injects all session traffic (keyboard/mouse/clipboard/files) = full remote-control compromise.
- **Attacker:** malicious/compromised rendezvous or relay server, or a network MITM on the controller↔server path (esp. self-hosted without configured client key, where client verifies against baked-in official `RS_PUB_KEY` and always mismatches → plaintext).
- **Open sub-questions (resolve in R2 + lab):**
  1. Does the controller ALWAYS set `secure=true` in its outgoing RequestRelay/punch, and is that field integrity-protected? (cleartext ⇒ flippable)
  2. Is `confirm_insecure_connection` mandatory + unbypassable, or silent/auto? (decides Medium vs High/Critical)
  3. Can a self-hosted deployment without distributed server pubkey be silently MITM'd (baked-in RS_PUB_KEY mismatch → plaintext)?
- **Severity:** confirmed **Medium** (downgrade path exists in code) / **potential Critical** (silent MITM → RCE-equivalent remote control if warning is weak/bypassable).
- **Disposition: needs-live-validation.** **Live test (lab):** build client+host+hbbs on the lab; MITM the relay leg; flip `RequestRelay.secure` bit / strip signed pk; observe whether the session runs plaintext and whether any un-dismissable warning appears. Vulnerable = plaintext session + no/weak warning; safe = connection refused or hard-blocked.
- **Cross-vendor:** Claude Critical; OpenAI High; my whole-flow read confirmed the code path (host `secure` from cleartext `RequestRelay.secure`; controller falls through on non-PublicKey without `bail!`, server.rs:244-246).

### F-C04 — `FramedStream::set_raw()` strips secretbox encryption for port-forward (cleartext downgrade?)
- **Component:** `hbb_common/tcp.rs` `set_raw` (143-146) drops `self.2` (the secretbox key); thereafter `send_raw` (158-165) / `next` (177-188) skip enc/dec. Callers: `src/port_forward.rs`, `src/server/connection.rs::try_port_forward_loop`.
- **Candidate root cause:** if the port-forward peer link uses `set_raw` and then relays tunneled bytes over the (direct/relay) network in plaintext, an on-path attacker / relay reads the forwarded traffic — a downgrade of RustDesk's E2E encryption.
- **Open question (R2):** confirm whether the raw stream is the network-facing peer link (real downgrade) or an already-inner pipe (designed). Code-confirmed that set_raw drops the key; caller semantics pending.
- **Verification:** Claude High; OpenAI High (needs-live-validation). **Severity: potential High (cleartext transmission of tunneled data). Disposition: needs-live-validation.**

## CORRECTED
_(none yet)_

## REJECTED (dedup set — do not resurface)
_(none yet)_

---

## Rejected-reason index (quick dedup keys)
_(append `component:function:bug-class → reason` as the judge rejects candidates)_
