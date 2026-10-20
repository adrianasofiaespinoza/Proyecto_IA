#!/usr/bin/env python3
"""Generate HTML reports: original vs patched file, raw diff, verdict and test evidence.
Read-only: it never changes frozen files, eval.json or results."""
import argparse, difflib, html, json, shutil, subprocess, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent

CSS = """
body{font-family:system-ui,sans-serif;margin:24px;max-width:1200px}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;margin:2px 6px 2px 0;font-weight:600;font-size:13px}
.ok{background:#d7f5dd;color:#14532d}.bad{background:#fde0e0;color:#7f1d1d}.na{background:#e5e7eb;color:#374151}
pre{background:#f6f8fa;padding:10px;overflow:auto;font-size:12px;border-radius:6px}
.add{color:#116329;background:#dafbe1}.del{color:#82071e;background:#ffebe9}.hunk{color:#0550ae}
table.diff{font-family:monospace;font-size:12px;border:1px solid #ccc;width:100%}
.diff_header{background:#e0e0e0}td.diff_header{text-align:right}
.diff_next{background:#c0c0c0}.diff_add{background:#aaffaa}.diff_chg{background:#ffff77}.diff_sub{background:#ffaaaa}
.box{border:1px solid #ddd;border-radius:8px;padding:12px 16px;margin:14px 0}
table.idx{border-collapse:collapse}table.idx td,table.idx th{border:1px solid #ccc;padding:4px 10px}
"""

def read_json(p):
    return json.loads(p.read_text()) if p.exists() else {}

def target_files(diff_text):
    files = []
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            path = line[4:].split("\t")[0].strip()
            if path.startswith("b/"):
                path = path[2:]
            if path != "/dev/null" and path not in files:
                files.append(path)
    return files

def original_text(vuln_dir, rel):
    r = subprocess.run(["git", "-C", str(vuln_dir), "show", f"HEAD:{rel}"],
                       capture_output=True, text=True)
    if r.returncode == 0:
        return r.stdout
    f = vuln_dir / rel
    return f.read_text(errors="replace") if f.exists() else None

def apply_patch(originals, patch_file):
    """Apply the frozen patch to temporary copies. Returns (patched dict or None, log)."""
    tmp = Path(tempfile.mkdtemp())
    try:
        for rel, txt in originals.items():
            if txt is not None:
                dst = tmp / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(txt)
        r = subprocess.run(["patch", "-p1", "--batch", "-d", str(tmp), "-i", str(patch_file.resolve())],
                           capture_output=True, text=True)
        log = (r.stdout or "") + (r.stderr or "")
        if r.returncode != 0:
            return None, log
        return {rel: (tmp / rel).read_text(errors="replace")
                for rel in originals if (tmp / rel).exists()}, log
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def tail(path, n=40):
    if path is None or not path.exists():
        return None
    return "\n".join(path.read_text(errors="replace").splitlines()[-n:])

def find_log(root, vid, kind, agent):
    for c in (root / "workspaces" / vid / "logs" / f"{kind}_{agent}_candidate.log",
              root / "evidence" / "test_logs" / vid / f"{kind}_{agent}_candidate.log"):
        if c.exists():
            return c
    return None

def badge(label, val, invert=False):
    if val is None:
        cls, shown = "na", "-"
    else:
        good = (val in (1, True)) != invert
        cls, shown = ("ok" if good else "bad"), val
    return f'<span class="badge {cls}">{label}={shown}</span>'

def color_diff(text):
    out = []
    for l in text.splitlines():
        if l.startswith("+") and not l.startswith("+++"):
            c = "add"
        elif l.startswith("-") and not l.startswith("---"):
            c = "del"
        elif l.startswith("@@"):
            c = "hunk"
        else:
            c = ""
        esc = html.escape(l)
        out.append(f'<span class="{c}">{esc}</span>' if c else esc)
    return "<pre>" + "\n".join(out) + "</pre>"

def conclusion(e):
    if e.get("status") != "complete":
        return "Verification incomplete: " + str(e.get("incomplete_reason"))
    if e.get("A") == 0:
        return "The patch could not be applied (malformed or does not match the code). No test was run."
    if e.get("V") == 1:
        return "Verified repair: the patch applies and both functional and exploit tests pass."
    if e.get("S") == 0 and e.get("F") == 1:
        return "The patch applies and keeps functionality, but the exploit still succeeds: the vulnerability remains."
    if e.get("S") == 0:
        return "The exploit still succeeds and the functional tests fail."
    return "Exploit tests pass but functional tests fail: the patch breaks existing behavior."

def build_case(root, runs, agent, vid, out_dir):
    run = runs / agent / vid
    e, g = read_json(run / "eval.json"), read_json(run / "generation.json")
    patch_file = run / "patch.diff"
    diff_text = patch_file.read_text(errors="replace") if patch_file.exists() else ""
    vuln_dir = root / "workspaces" / vid / "vulnerable"
    files = target_files(diff_text)
    originals = {rel: original_text(vuln_dir, rel) for rel in files}
    patched, plog = (apply_patch(originals, patch_file) if diff_text else (None, "no patch.diff"))

    h = [f"<html><head><meta charset='utf-8'><title>{vid}</title><style>{CSS}</style></head><body>",
         f"<h1>{html.escape(vid)}</h1><p><a href='index.html'>&larr; index</a></p>"]

    h.append("<div class='box'><h2>Verdict</h2>")
    h.append(badge("C (claim)", e.get("C")) + f'<span class="badge na">P={e.get("P")}</span>')
    h.append(badge("A", e.get("A")) + badge("F", e.get("F")) + badge("S", e.get("S")) +
             badge("V", e.get("V")) + badge("FA", e.get("FA"), invert=True))
    h.append(f"<p><b>{html.escape(conclusion(e))}</b></p>")
    if e.get("FA") == 1:
        h.append(f"<p><b>False assurance:</b> the model claimed success with confidence {e.get('P')}.</p>")
    h.append(f"<p>Model: {html.escape(str(g.get('model')))} | latency: {g.get('latency_ms')} ms | "
             f"tokens in/out: {g.get('input_tokens')}/{g.get('output_tokens')}</p></div>")

    h.append("<div class='box'><h2>Diff produced by the model (frozen)</h2>")
    h.append(color_diff(diff_text) if diff_text else "<p>No patch.</p>")
    h.append("</div>")

    h.append("<div class='box'><h2>Original vs patched file</h2>")
    if patched is None:
        h.append("<p>The patch does not apply, so there is no patched file. Patch tool output:</p>")
        h.append(f"<pre>{html.escape(plog)}</pre>")
    else:
        hd = difflib.HtmlDiff(tabsize=4, wrapcolumn=90)
        for rel in files:
            if originals.get(rel) is None or rel not in patched:
                continue
            h.append(f"<h3>{html.escape(rel)}</h3>")
            h.append(hd.make_table(originals[rel].splitlines(), patched[rel].splitlines(),
                                   "Original", "Patched", context=True, numlines=3))
    h.append("</div>")

    h.append("<div class='box'><h2>Test evidence (end of logs)</h2>")
    for kind in ("patch", "functional", "exploit"):
        t = tail(find_log(root, vid, kind, agent))
        h.append(f"<h3>{kind}</h3>" + (f"<pre>{html.escape(t)}</pre>" if t else "<p>No log found.</p>"))
    h.append("</div></body></html>")
    (out_dir / f"{vid}.html").write_text("\n".join(h), encoding="utf-8")
    return e

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=Path, default=HERE / "runs" / "midterm")
    ap.add_argument("--agent", default="gpt")
    ap.add_argument("--out", type=Path, default=HERE / "report")
    ap.add_argument("--root", type=Path, default=HERE)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)

    rows = []
    for d in sorted((a.runs / a.agent).iterdir()):
        if d.is_dir() and (d / "eval.json").exists():
            e = build_case(a.root, a.runs, a.agent, d.name, a.out)
            rows.append((d.name, e))

    done = [e for _, e in rows if e.get("status") == "complete"]
    sumC = sum(e["C"] for e in done)
    far = f"{sum(e['FA'] for e in done)}/{sumC}" if sumC else "undefined"
    h = [f"<html><head><meta charset='utf-8'><title>Report</title><style>{CSS}</style></head><body>",
         "<h1>False assurance report</h1>",
         f"<p>N completed = {len(done)} | VRR = {sum(e['V'] for e in done)}/{len(done)} | FAR = {far}</p>",
         "<table class='idx'><tr><th>Case</th><th>C</th><th>P</th><th>A</th><th>F</th><th>S</th><th>V</th><th>FA</th><th>Status</th></tr>"]
    for vid, e in rows:
        h.append(f"<tr><td><a href='{vid}.html'>{vid}</a></td>" +
                 "".join(f"<td>{e.get(k)}</td>" for k in ("C", "P", "A", "F", "S", "V", "FA", "status")) + "</tr>")
    h.append("</table></body></html>")
    (a.out / "index.html").write_text("\n".join(h), encoding="utf-8")
    print(f"[+] wrote {len(rows)} case pages and {a.out / 'index.html'}")

if __name__ == "__main__":
    main()
