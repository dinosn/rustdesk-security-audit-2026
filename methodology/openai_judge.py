#!/usr/bin/env python3
"""Cross-vendor OpenAI judge for RustDesk loop-hunt survivors.
Usage: openai_judge.py <survivors.json> <out.json>
survivors.json: list of candidate dicts (must have file; line/function/title/claim optional).
Routes through RAPTOR's LLMClient (respects configured provider/base_url)."""
import os, sys, json, re
os.environ.setdefault("RAPTOR_DIR", "/Users/krasn/tools/raptor")
sys.path.insert(0, os.environ["RAPTOR_DIR"])
from core.llm.client import LLMClient

SYS = (
 "You are a meticulous, adversarial security JUDGE giving an independent cross-vendor second opinion "
 "on another model's vulnerability claim about RustDesk (peer-to-peer remote desktop; hbbs=rendezvous server, "
 "hbbr=relay; client parses untrusted peer/server messages; NaCl box/sign secure channel). "
 "Default to REFUTED unless the cited code PROVES the bug. You may REJECT only with an OBSERVED reason you can "
 "point to in the provided source: cited code doesn't do what the claim says; entry point not attacker-reachable; "
 "a mitigating check is PRESENT (cite line); or designed behavior under the trust model. "
 "INVALID refutations: 'a real server probably handles it', 'framework likely validates', 'needs non-default config' "
 "(unless the default is shown), 'not built/loaded' (unless shown). Assuming an UNSEEN layer is secure is NOT refutation. "
 "If the ONLY barrier is a layer not in the provided source (peer/host runtime, another file) -> verdict "
 "needs-live-validation, keep worst-case severity, give an exact safe live_test. "
 "Scope focus: RCE, auth-bypass, MITM, arbitrary file write, local privesc. Pure-DoS is low priority. "
 "Output STRICT JSON only, no prose outside it."
)

def read_source(path, line, whole_cap=1400, radius=220):
    try:
        with open(path, "r", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        return f"<<could not read {path}: {e}>>"
    n = len(lines)
    if n <= whole_cap:
        lo, hi = 0, n
    else:
        c = (line or 1) - 1
        lo, hi = max(0, c - radius), min(n, c + radius)
    return "".join(f"{i+1}\t{lines[i]}" for i in range(lo, hi))

def main():
    survivors = json.load(open(sys.argv[1]))
    client = LLMClient(pinned_model=os.environ.get("JUDGE_MODEL", "openai/gpt-5.4"))
    out = []
    for c in survivors:
        f = c.get("file") or ""
        src = read_source(f, c.get("line")) if f else "<<no file provided>>"
        prompt = (
            f"CANDIDATE CLAIM (from another model):\n{json.dumps(c, indent=2, default=str)}\n\n"
            f"CITED SOURCE ({f}):\n{src}\n\n"
            "Re-derive independently from the source above. Return STRICT JSON with keys: "
            "verdict (one of confirmed|needs-live-validation|corrected|rejected), reason (cite line numbers), "
            "observed_mitigation (or ''), final_severity (Critical|High|Medium|Low), exploitability (one line), "
            "live_test (exact safe test + expected vulnerable-vs-safe result, or '')."
        )
        try:
            r = client.generate(prompt, system_prompt=SYS, task_type="analysis")
            txt = getattr(r, "content", None) or str(r)
        except Exception as e:
            txt = ""
            verdict = {"verdict": "judge-error", "reason": f"{type(e).__name__}: {e}"}
        else:
            m = re.search(r"\{.*\}", txt, re.S)
            try:
                verdict = json.loads(m.group(0)) if m else {"verdict": "parse-error", "reason": txt[:600]}
            except Exception as e:
                verdict = {"verdict": "parse-error", "reason": f"{e}; raw={txt[:400]}"}
        out.append({"candidate": c, "openai_verdict": verdict})
        sys.stderr.write(f"[{verdict.get('verdict','?'):22}] {str(c.get('title','?'))[:64]}\n")
    json.dump(out, open(sys.argv[2], "w"), indent=2, default=str)
    sys.stderr.write(f"wrote {len(out)} OpenAI verdicts -> {sys.argv[2]}\n")

if __name__ == "__main__":
    main()
