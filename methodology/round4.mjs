export const meta = {
  name: 'rustdesk-r4-variant-hunt',
  description: 'RustDesk loop-hunt Round 4: variant-hunt siblings of the confirmed-bug clusters (permission-gate bypass, self-reported-identity trust, secure-channel skip, client-trusts-server) + verification of gaps + thin cells; each judged from raw',
  phases: [ { title:'Generate' }, { title:'Judge' } ],
}
const T='/Users/krasn/tools/raptor/targets/rustdesk'
const S=`${T}/src`, HBB=`${T}/libs/hbb_common/src`

const PRIMER=`RustDesk P2P remote desktop. Round 4 = VARIANT HUNT: find SIBLINGS of already-CONFIRMED bugs (same root-cause pattern, different location). Confirmed seed patterns to find MORE of:
- PERM-GATE-BYPASS: a peer message/action performed WITHOUT re-checking its ControlPermissions gate (keyboard/file/clipboard/audio/camera/terminal/tunnel/restart/recording/block_input/remote_modify/privacy_mode). Seeds: Cliprdr processed w/o clipboard perm; switch-sides skips tunnel perm; non-ASCII keyboard writes clipboard w/o clipboard perm.
- SELF-REPORTED-IDENTITY TRUST: authz/identity decided by a NON-SECRET peer-supplied value (hwid, uuid=machine_uid, device id, my_id) with no crypto proof. Seeds: RegisterPk pk-substitution (uuid=machine_uid, on-wire); 2FA trusted-device bypass (self-reported hwid).
- SECURE-CHANNEL SKIP: a transport/parse path that does NOT apply the NaCl secretbox (set_key no-op, raw mode, a frame type returned undecrypted). Seeds: WsFramedStream Text frames unauthenticated; set_raw() drops key for port-forward; RequestRelay.secure=false forces plaintext. NOTE webrtc.rs set_key is a no-op — verify whether WebRTC transport applies RustDesk's secretbox at all.
- CLIENT-TRUSTS-SERVER-MSG: client acts on / persists an unauthenticated server/rendezvous message. Seeds: ConfigureUpdate persists rendezvous-servers+restart over unauth UDP.
Report NEW instances/variants; do NOT re-report the seeds themselves. Also VERIFY the named gaps. Check permission enforcement is at the RUST layer (Dart UI checks don't count).`

const CONTRACT=`For EACH candidate: title, component, file(abs), line(int), function, bug_class, root_cause("<fn> in <file> does not <check>, allowing <consequence>"), entry_point, sink, trace, attack(attacker,exact input,observed result), preconditions(permission? default? feature-gate — check Cargo.toml), severity, potential_severity, confidence(0..1)+confidence_reason, disposition_hint. Real entry+sink+trace each. Read RAW (Grep huge files for the message match / permission checks / set_key / hwid). DEPRIORITIZE pure-DoS. Cite exact code. A NEW missing-gate or NEW unauth-identity-trust or NEW enc-skip is the goal.`

const GEN_SCHEMA={type:'object',properties:{reviewed_files:{type:'array',items:{type:'string'}},candidates:{type:'array',items:{type:'object',properties:{title:{type:'string'},component:{type:'string'},file:{type:'string'},line:{type:'integer'},function:{type:'string'},bug_class:{type:'string'},root_cause:{type:'string'},entry_point:{type:'string'},sink:{type:'string'},trace:{type:'string'},attack:{type:'string'},preconditions:{type:'string'},severity:{type:'string'},potential_severity:{type:'string'},confidence:{type:'number'},confidence_reason:{type:'string'},disposition_hint:{type:'string'}},required:['title','file','function','bug_class','root_cause','entry_point','sink','attack','severity','confidence']}}},required:['candidates']}
const JUDGE_SCHEMA={type:'object',properties:{verdict:{type:'string',enum:['confirmed','needs-live-validation','corrected','rejected']},reason:{type:'string'},observed_mitigation:{type:'string'},corrected_severity:{type:'string'},corrected_root_cause:{type:'string'},live_test:{type:'string'},final_severity:{type:'string'},confidence:{type:'number'}},required:['verdict','reason']}

const CELLS=[
 {key:'permgate-conn-a', files:[`${S}/server/connection.rs`],
  lens:'PERM-GATE variant hunt (part A). Grep the peer-message dispatch (match on Message union / on_message). For EACH message type that performs an action (input, clipboard, file, audio, recording, restart, options, switch-sides, elevation, terminal), verify a ControlPermissions/authorized check runs BEFORE the action. Report every message handler MISSING its gate or checking the wrong permission.'},
 {key:'permgate-conn-b', files:[`${S}/server/connection.rs`,`${S}/server/input_service.rs`],
  lens:'PERM-GATE variant hunt (part B): input/keyboard/mouse/block-input + options + 2FA/password state transitions. Verify keyboard/mouse injection is gated by keyboard perm AND respects block_input/privacy state; verify option/setting messages cannot change security posture without authz. Report missing/incorrect gates.'},
 {key:'self-identity', files:[`${S}/server/connection.rs`,`${S}/auth_2fa.rs`,`${S}/ipc/auth.rs`,`${HBB}/config.rs`],
  lens:'SELF-REPORTED-IDENTITY-TRUST variant hunt. Find every authz/identity/trust decision keyed on a peer-supplied or machine-derived NON-SECRET value (hwid, uuid, machine_uid, my_id, device id, guid, session id) with no cryptographic proof-of-possession. Seeds: register_pk uuid, 2FA hwid. Report NEW ones (e.g. trusted-device store, whitelist by id, session resumption).'},
 {key:'enc-skip', files:[`${HBB}/webrtc.rs`,`${HBB}/stream.rs`,`${HBB}/websocket.rs`,`${S}/kcp_stream.rs`],
  lens:'SECURE-CHANNEL-SKIP variant hunt. For EACH transport/wrapper, verify it applies the NaCl secretbox (enc on send, dec+auth on recv) for ALL frame types. webrtc.rs set_key appears to be a no-op — determine if WebRTC-transported sessions get RustDesk secretbox at all or rely solely on DTLS. Report any transport/frame-type that carries session data unauthenticated/unencrypted.'},
 {key:'client-trusts-server', files:[`${S}/rendezvous_mediator.rs`,`${S}/client.rs`,`${S}/client/io_loop.rs`],
  lens:'CLIENT-TRUSTS-SERVER-MSG variant hunt. Beyond ConfigureUpdate, find every client-side handler of a rendezvous/server/peer message that PERSISTS config, triggers a connection/relay to a server-supplied address, launches an update/process, or changes security state — reachable without authenticating the sender. Report each.'},
 {key:'fs-write-gap', files:[`${HBB}/fs.rs`],
  lens:'VERIFY file-write gaps. (1) single-file transfer empty-name exemption (validate_transfer_file_names lines ~491-495): does the metadata/destination path for a single-file DOWNLOAD skip validate_file_name_no_traversal, allowing ../ or absolute? (2) write()/set_stream_offset derived .download/.digest sibling paths vs symlink check. (3) any write path NOT routed through join_validated_path. Report concrete arbitrary-write/traversal.'},
 {key:'auth-flow', files:[`${S}/auth_2fa.rs`,`${S}/server/login_failure_check.rs`,`${HBB}/password_security.rs`,`${S}/server/connection.rs`],
  lens:'Full AUTH flow bypass hunt + verify. Password verify (constant-time?), one-time/permanent password entropy + rate-limit/lockout (login_failure_check — per-IP only? distributed bypass?), 2FA TOTP verify + trusted-device store, ip whitelist. Report bypasses: brute-force feasibility, timing, replay, trusted-device forgery, lockout bypass.'},
 {key:'kcp-mem', files:[`${S}/kcp_stream.rs`,`${HBB}/mem.rs`],
  lens:'KCP stream framing/state on attacker segments + mem.rs unsafe. Hunt: memory/int-overflow/UAF in kcp segment handling, unsafe blocks in mem.rs (transmute/from_raw/set_len), buffer math.'},
 {key:'ipc-variants', files:[`${S}/ipc.rs`,`${S}/ipc/auth.rs`,`${S}/ipc/fs.rs`],
  lens:'LOCAL IPC authz variant hunt (beyond the confirmed Windows cross-session one). For each IPC message/op, verify the caller is authorized (peer-cred/session check) before privileged action (fs op as service, config write, elevation, password read). Report any unauthenticated privileged IPC op → local privesc / secret disclosure.'},
 {key:'thin-cells', files:[`${T}/libs/portable/src/lib.rs`,`${S}/port_forward.rs`,`${HBB}/socket_client.rs`],
  lens:'Thin remaining cells. portable exe extraction (path/arb-write on unpack), port_forward tunnel target validation (SSRF/arbitrary internal connect from a peer-supplied target), socket_client connect-target validation. Report concrete issues.'},
]

phase('Generate'); log(`Round 4 variant-hunt: ${CELLS.length} generators`)
const results=await pipeline(CELLS,
 (cell)=>agent(`${PRIMER}\n\nIsolated generator. Slice: ${cell.key}.\nRead RAW (Grep huge files first):\n${cell.files.map(f=>'  '+f).join('\n')}\n\nHUNT LENS: ${cell.lens}\n\n${CONTRACT}\n\nReturn ONLY the structured object.`,
   {label:`gen:${cell.key}`,phase:'Generate',schema:GEN_SCHEMA,model:'sonnet'}).then(r=>({cell:cell.key,...(r||{candidates:[]})})),
 (gen,cell)=>{const cands=(gen&&gen.candidates)?gen.candidates:[]; if(!cands.length)return {cell:cell.key,judged:[]};
   return parallel(cands.map(c=>()=>agent(`${PRIMER}\n\nIndependent JUDGE, re-derive from raw. RE-READ file=${c.file} fn=${c.function} + callers. Verify the permission/auth check is ABSENT at the RUST enforcement layer (not just Dart).\n\nCANDIDATE:\n${JSON.stringify(c,null,2)}\n\nREJECT only with an OBSERVED reason (mitigating check PRESENT cite line / not reachable / designed / feature-gated / already-a-known-seed not a new variant). INVALID: assuming unseen layer secure. Unobservable barrier -> needs-live-validation+live_test. Mis-rated -> corrected. Provable -> confirmed. Permission-gated-action-misused < ungated. Return ONLY verdict.`,
     {label:`judge:${cell.key}:${(c.title||'').slice(0,20)}`,phase:'Judge',schema:JUDGE_SCHEMA,model:'sonnet'}).then(v=>({candidate:c,verdict:v||{verdict:'rejected',reason:'judge-null'}}))
   )).then(judged=>({cell:cell.key,judged}))})
const out=[]; for(const r of results.filter(Boolean))for(const j of (r.judged||[]))out.push({cell:r.cell,...j})
const kept=out.filter(o=>o.verdict&&o.verdict.verdict&&o.verdict.verdict!=='rejected')
log(`Round 4 done: ${out.length} candidates, ${kept.length} survive`)
return {round:4,total:out.length,survivors:kept,rejected:out.filter(o=>!kept.includes(o))}
