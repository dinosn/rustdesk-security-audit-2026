# RustDesk — Component Inventory (Coverage Denominator)

The completeness gate. Every component below must end each engagement either **covered**
(with the round that covered it) or **omitted** (with an explicit reason). Silent omission
is a methodology failure. Coverage state is tracked in `TRIED.md`.

Targets:
- **client** `rustdesk` @ `137298e` (Rust ~142K LoC + Dart ~71K LoC)
- **server** `rustdesk-server` @ `91fb928` (Rust ~3.4K LoC)
- **shared** `hbb_common` submodule — client pin `7e1c392`, server pin `83419b6` (VERSION SKEW — track)

Legend: status ∈ {UNCOVERED, IN-PROGRESS, COVERED(rN), OMITTED(reason)}

## A. hbb_common — shared protocol/crypto/net (CRITICAL: bug here hits client AND server)
| # | Component | File(s) | Primary bug-classes | Priority | Status |
|---|-----------|---------|--------------------|----------|--------|
| A1 | Frame codec | bytes_codec.rs | int-overflow, alloc-bomb, OOB | R1 | UNCOVERED |
| A2 | Compression | compress.rs | decompression bomb, OOB | R1 | UNCOVERED |
| A3 | Config/keystore | config.rs, config/ | key handling, path, injection | R2 | UNCOVERED |
| A4 | Fingerprint/verify | fingerprint.rs, verifier.rs | auth-bypass, MITM, weak-compare | R2 | UNCOVERED |
| A5 | Password security | password_security.rs | weak-crypto, timing, hash | R2 | UNCOVERED |
| A6 | File transfer proto | fs.rs | path-traversal, arb-write | R3 | UNCOVERED |
| A7 | Proxy | proxy.rs | SSRF, cred-leak | R6 | UNCOVERED |
| A8 | Transports | tcp.rs, udp.rs, stream.rs, tls.rs, socket_client.rs, websocket.rs, webrtc.rs | framing, TLS-verify, MITM | R1 | UNCOVERED |
| A9 | Protobuf schema | protos/message.proto, rendezvous.proto | attack surface enum (not a bug site) | R1 | UNCOVERED |
| A10 | Memory utils | mem.rs | unsafe, UB | R4 | UNCOVERED |
| A11 | Keyboard map | keyboard.rs | logic | R7 | UNCOVERED |
| A12 | hbb platform | platform/ | OS-specific | R5 | UNCOVERED |

## B. rustdesk-server (pre-auth network daemons — CRITICAL)
| # | Component | File(s) | Primary bug-classes | Priority | Status |
|---|-----------|---------|--------------------|----------|--------|
| B1 | Rendezvous (hbbs) | rendezvous_server.rs | pre-auth parse, logic, spoof | R1 | UNCOVERED |
| B2 | Relay (hbbr) | relay_server.rs, hbbr.rs | pre-auth, unauthorized relay, amplification | R1 | UNCOVERED |
| B3 | Peer registry | peer.rs | spoof, memory, state | R1 | UNCOVERED |
| B4 | Database | database.rs | SQLi, injection | R1 | UNCOVERED |
| B5 | Server common/utils | common.rs, utils.rs | logic, key handling | R1 | UNCOVERED |
| B6 | Server entry | main.rs, lib.rs, mod.rs | config, arg | R5 | UNCOVERED |

## C. client src — connection handling (host side = being controlled) (HIGH)
| # | Component | File(s) | Primary bug-classes | Priority | Status |
|---|-----------|---------|--------------------|----------|--------|
| C1 | Connection handler | server/connection.rs | authz, login-bypass, msg-parse | R2 | UNCOVERED |
| C2 | Server core | server.rs, server/service.rs | dispatch | R2 | UNCOVERED |
| C3 | Clipboard service | server/clipboard_service.rs | inject, path | R3 | UNCOVERED |
| C4 | Input service | server/input_service.rs, rdp_input.rs, uinput.rs | unauthorized-input, injection | R7 | UNCOVERED |
| C5 | Video service | server/video_service.rs, video_qos.rs | capture, resource | R7 | UNCOVERED |
| C6 | Audio service | server/audio_service.rs | resource | R7 | UNCOVERED |
| C7 | Display service | server/display_service.rs | logic | R7 | UNCOVERED |
| C8 | Terminal service | server/terminal_service.rs, terminal_helper.rs | cmd-exec, authz | R6 | UNCOVERED |
| C9 | Printer service | server/printer_service.rs | file, spool | R6 | UNCOVERED |
| C10 | Portable service | server/portable_service.rs | shmem, privesc | R5 | UNCOVERED |
| C11 | Login failure check | server/login_failure_check.rs | brute-force, lockout-bypass | R2 | UNCOVERED |
| C12 | Wayland/dbus | server/wayland.rs, dbus.rs | logic | R7 | UNCOVERED |

## D. client src — session (controller side = controlling remote) (HIGH: malicious host attacks controller)
| # | Component | File(s) | Primary bug-classes | Priority | Status |
|---|-----------|---------|--------------------|----------|--------|
| D1 | IO loop / msg decode | client/io_loop.rs | parse untrusted host msgs, memory | R2 | UNCOVERED |
| D2 | Client core | client.rs, client/helper.rs | handshake, crypto | R2 | UNCOVERED |
| D3 | File recv | client/file_trait.rs | path-traversal, arb-write | R3 | UNCOVERED |
| D4 | Screenshot | client/screenshot.rs | path, file | R3 | UNCOVERED |

## E. client src — crypto/auth/rendezvous (CRITICAL)
| # | Component | File(s) | Primary bug-classes | Priority | Status |
|---|-----------|---------|--------------------|----------|--------|
| E1 | 2FA | auth_2fa.rs | bypass, weak, replay | R2 | UNCOVERED |
| E2 | Rendezvous mediator | rendezvous_mediator.rs | parse server msgs, spoof, MITM | R1 | UNCOVERED |
| E3 | KCP stream | kcp_stream.rs | framing, memory | R1 | UNCOVERED |
| E4 | LAN discovery | lan.rs | UDP broadcast parse, spoof | R1 | UNCOVERED |
| E5 | Port forward | port_forward.rs | SSRF, unauthorized tunnel | R6 | UNCOVERED |
| E6 | Custom server | custom_server.rs | config-injection, deser | R6 | UNCOVERED |

## F. client src — IPC (local privilege boundary; service runs elevated) (HIGH: local privesc)
| # | Component | File(s) | Primary bug-classes | Priority | Status |
|---|-----------|---------|--------------------|----------|--------|
| F1 | IPC core | ipc.rs | auth, cmd-injection, privesc | R5 | UNCOVERED |
| F2 | IPC auth | ipc/auth.rs | authz-bypass | R5 | UNCOVERED |
| F3 | IPC fs | ipc/fs.rs | path-traversal | R5 | UNCOVERED |

## G. client src — HTTP API client (MEDIUM)
| # | Component | File(s) | Primary bug-classes | Priority | Status |
|---|-----------|---------|--------------------|----------|--------|
| G1 | HTTP core | hbbs_http.rs, hbbs_http/http_client.rs | TLS-verify, SSRF | R6 | UNCOVERED |
| G2 | Account | hbbs_http/account.rs | token, auth | R6 | UNCOVERED |
| G3 | Sync | hbbs_http/sync.rs | data | R6 | UNCOVERED |
| G4 | Downloader | hbbs_http/downloader.rs | path, TLS, arb-write | R6 | UNCOVERED |
| G5 | Record upload | hbbs_http/record_upload.rs | path | R6 | UNCOVERED |

## H. client src — plugin system (HIGH: native code loading)
| # | Component | File(s) | Primary bug-classes | Priority | Status |
|---|-----------|---------|--------------------|----------|--------|
| H1 | Plugin native/loader | plugin/native.rs, plugins.rs, manager.rs | RCE, unsigned load, supply-chain | R6 | UNCOVERED |
| H2 | Plugin handlers | plugin/native_handlers/* | callback, memory | R6 | UNCOVERED |
| H3 | Plugin config/ipc | plugin/config.rs, ipc.rs, callback_* , desc.rs | injection | R6 | UNCOVERED |

## I. client src — updater / supply-chain (HIGH)
| # | Component | File(s) | Primary bug-classes | Priority | Status |
|---|-----------|---------|--------------------|----------|--------|
| I1 | Updater | updater.rs | sig-verify-bypass, downgrade, arb-write | R6 | UNCOVERED |

## J. client src — platform / privesc (HIGH)
| # | Component | File(s) | Primary bug-classes | Priority | Status |
|---|-----------|---------|--------------------|----------|--------|
| J1 | Windows | platform/windows.rs, win_device.rs, windows/acl.rs | ACL, privesc, service | R5 | UNCOVERED |
| J2 | Linux | platform/linux.rs, gtk_sudo.rs, linux_desktop_manager.rs | sudo, env-inject, privesc | R5 | UNCOVERED |
| J3 | macOS | platform/macos.rs, delegate.rs | privesc | R5 | UNCOVERED |
| J4 | Privacy mode | privacy_mode.rs, privacy_mode/* | logic | R7 | UNCOVERED |

## K. client libs — media/codec (HIGH: memory corruption on attacker frames)
| # | Component | File(s) | Primary bug-classes | Priority | Status |
|---|-----------|---------|--------------------|----------|--------|
| K1 | scrap codec decode | libs/scrap/src/*.rs (codec, vpxcodec, aom, hwcodec, decoder) | OOB, int-overflow, UAF on decode | R4 | UNCOVERED |
| K2 | scrap capture | libs/scrap/src (dxgi, quartz, x11, wayland, camera) | capture, mostly non-attacker | R7 | UNCOVERED |
| K3 | clipboard lib | libs/clipboard/* | parse, path, inject | R3 | UNCOVERED |
| K4 | enigo | libs/enigo/* | input-inject | R7 | UNCOVERED |
| K5 | virtual_display | libs/virtual_display/* | driver ioctl | R5 | UNCOVERED |
| K6 | remote_printer | libs/remote_printer/* | file, spool | R6 | UNCOVERED |
| K7 | portable | libs/portable/* | extract, path | R5 | UNCOVERED |

## L. client — Flutter/Dart UI + logic (MEDIUM: logic/authz, not memory)
| # | Component | File(s) | Primary bug-classes | Priority | Status |
|---|-----------|---------|--------------------|----------|--------|
| L1 | FFI boundary | src/flutter_ffi.rs, flutter.rs | type-confusion, cmd surface | R8 | UNCOVERED |
| L2 | Dart connection/session | flutter/lib/**/*.dart | permission/authz logic | R8 | UNCOVERED |
| L3 | Dart password/security gate | flutter/lib (models, permissions) | unattended-access, gating | R8 | UNCOVERED |

## M. client — UI glue / misc (LOWER)
| # | Component | File(s) | Priority | Status |
|---|-----------|---------|----------|--------|
| M1 | Core main / entry | core_main.rs, main.rs, lib.rs, service.rs, common.rs | R5 | UNCOVERED |
| M2 | UI interfaces | ui*.rs, ui/*, tray.rs | R8 | UNCOVERED |
| M3 | Whiteboard | whiteboard/* | R8 | UNCOVERED |
| M4 | Naming/keyboard/misc | naming.rs, keyboard.rs, virtual_display_manager.rs | R7 | UNCOVERED |

## OMITTED (with reason)
- **src/lang/\*.rs** — static i18n translation string tables; no attacker-reachable logic. OMITTED(non-security-data).
- **libs/libxdo-sys-stub** — trivial stub shim, no logic. OMITTED(trivial-stub).
- **flutter/ platform build scaffolding, generated bindings** — build artifacts. OMITTED(generated/build) unless a specific .dart logic file is pulled into L2/L3.
- **Transitive dependency CVEs** — captured deterministically in `sca-client.json`/`sca-server.json`; EXCLUDED from LLM hunt scope per methodology (log-and-exclude). Reachability notes carried in TRIED.md Round 0.
