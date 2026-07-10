# RustDesk hbbs live-PoC results (lab root@192.168.1.119, hbbs @ server 91fb928, Docker rust:bookworm)

Ran `poc_rendezvous.py` against a live `hbbs` (UDP :21116, default config, no `-k` key).

## F-C03 — RegisterPk pk-substitution (same-IP && guard bypass) — VULNERABLE (live)
- legit RegisterPk{id=poc12345, uuid=U, pk=0x11*32} → DB pk = 11..11
- attacker RegisterPk{id=poc12345, uuid=U (same, sniffable on-wire), pk=0xAA*32} from SAME source IP → DB pk = AA..AA  (OVERWRITTEN)
- control RegisterPk{id=poc12345, uuid=WRONG, pk=0xCC*32} → REJECTED, DB pk stays AA..AA
- Proves: the only ownership barrier is the uuid (=cleartext machine_uid on the wire); the `if peer.info.ip != ip && peer.pk != rk.pk` guard (rendezvous_server.rs:360) lets a same-source-IP attacker who knows/sniffed the uuid overwrite the server-pinned pk → persistent ID hijack / MITM of future controllers.
- Full remote precondition: on-path sniff of the uuid + source-IP spoof (UDP, blind) OR shared-NAT/on-path. Server mechanic = definitively proven.

## F-S04 — Unauthenticated UDP reflector (forged AddrMangle) — VULNERABLE (live)
- victim UDP listener 127.0.0.1:36196 never contacted hbbs.
- attacker → hbbs: PunchHoleSent{socket_addr=AddrMangle(127.0.0.1:36196)}
- victim received 16 bytes (PunchHoleResponse, wire 5a0e0a0a..) reflected from hbbs.
- Proves: AddrMangle::decode is unauthenticated arithmetic; handle_hole_sent (rendezvous_server.rs:634) sends to the attacker-chosen decoded address with no auth/rate-limit → confused-deputy reflector (DoS-class; deprioritized per scope but confirmed).
