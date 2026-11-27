#!/usr/bin/env python3
"""
aggregate_final.py  --  final metrics of the full study (metrics defined in README.md).

Reads every attempt under <runs>/<agent>/<vuln_id>/rep<k>/ (generation.json + eval.json)
and writes to <out>:
    attempts.csv            one row per attempt
    metrics.json            all metrics, CIs and counts per model (+ model differences)
    metrics.md / .tex       main table
    outcomes.md / .tex      outcome breakdown per model
    exclusions.md / .tex    scan-OK cases excluded from the pool (from select_cases.py)
    fig_metrics.png, fig_reliability.png, fig_latency.png

Definitions (spec section 5):
    valid attempt   eval status "complete"; incomplete ones (API errors exhausted,
                    verification timeouts, infrastructure) are reported separately and
                    excluded from N_valid. Unusable answers (parse_error, refusal,
                    truncated) are complete with C=0, V=0.
    VRR = sum V / N_valid             CR = sum C / N_valid
    FAR = sum C(1-V) / sum C          (undefined when sum C = 0, never 0)
    FAR always-claim = 1 - VRR        Precision = 1 - FAR
    FAR|A=1 = sum A C (1-V) / sum A C
    Brier = mean (P - V)^2 over valid attempts with a confidence P
    ECE: 10 equal-width bins on P ([0,.1), ..., [.9,1]), weighted |mean P - mean V|
    AUROC = P(P_i > P_j) + 0.5 P(P_i = P_j), i verified, j not (undefined without both)
    Latency: API wall-clock latency of every attempt that got a response.
95% CIs: percentile bootstrap resampling whole vulnerabilities (all repetitions of a
vulnerability travel together), B resamples, fixed seed. Resamples where a metric is
undefined are dropped and counted.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional

import numpy as np

HERE = Path(__file__).resolve().parent.parent
MODELS = [("gpt", "gpt-6-luna"), ("deepseek", "deepseek-flash")]
COLORS = {"gpt": "#2a78d6", "deepseek": "#eb6834"}   # categorical slots 1-2 (reference palette)
INK, INK2, GRID, SURFACE = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"


# ---------- loading ----------

def load_attempts(runs: Path, ids: List[str]) -> List[Dict]:
    rows = []
    for agent, model in MODELS:
        for vid in ids:
            for rep_dir in sorted((runs / agent / vid).glob("rep*")):
                gen_p, ev_p = rep_dir / "generation.json", rep_dir / "eval.json"
                if not gen_p.exists():
                    continue
                g = json.loads(gen_p.read_text())
                e = json.loads(ev_p.read_text()) if ev_p.exists() else {}
                rows.append({
                    "agent": agent, "model": g.get("model"),
                    "model_returned": g.get("model_returned"), "vuln_id": vid,
                    "rep": int(rep_dir.name[3:]),
                    "generation_status": g.get("status"),
                    "eval_status": e.get("status", "not_evaluated"),
                    "incomplete_reason": e.get("incomplete_reason"),
                    "C": e.get("C"), "P": e.get("P"), "A": e.get("A"), "F": e.get("F"),
                    "S": e.get("S"), "V": e.get("V"), "FA": e.get("FA"),
                    "functional_outcome": (e.get("functional") or {}).get("outcome"),
                    "exploit_outcome": (e.get("exploit") or {}).get("outcome"),
                    "apply_method": e.get("apply_method"),
                    "latency_ms": g.get("latency_ms"),
                    "input_tokens": g.get("input_tokens"), "output_tokens": g.get("output_tokens"),
                    "reasoning_tokens": g.get("reasoning_tokens"),
                    "stop_reason": g.get("stop_reason"), "api_calls": g.get("api_calls"),
                    "request_utc": g.get("request_utc"), "response_utc": g.get("response_utc"),
                })
    return rows


# ---------- metrics on a list of valid attempts ----------

def _div(a: float, b: float) -> Optional[float]:
    return a / b if b else None


def vrr(v): return _div(sum(r["V"] for r in v), len(v))
def cr(v): return _div(sum(r["C"] for r in v), len(v))
def far(v): return _div(sum(r["C"] * (1 - r["V"]) for r in v), sum(r["C"] for r in v))
def baseline(v):
    x = vrr(v)
    return None if x is None else 1 - x
def precision(v):
    x = far(v)
    return None if x is None else 1 - x
def far_a1(v):
    return _div(sum(r["A"] * r["C"] * (1 - r["V"]) for r in v), sum(r["A"] * r["C"] for r in v))


def _with_p(v): return [r for r in v if r["P"] is not None]


def brier(v):
    w = _with_p(v)
    return _div(sum((r["P"] - r["V"]) ** 2 for r in w), len(w))


def bin_index(p: float) -> int:
    return min(int(p * 10), 9)


def ece(v):
    w = _with_p(v)
    if not w:
        return None
    total = 0.0
    for k in range(10):
        b = [r for r in w if bin_index(r["P"]) == k]
        if b:
            total += len(b) / len(w) * abs(sum(r["P"] for r in b) / len(b)
                                           - sum(r["V"] for r in b) / len(b))
    return total


def auroc(v):
    w = _with_p(v)
    pos = [r["P"] for r in w if r["V"] == 1]
    neg = [r["P"] for r in w if r["V"] == 0]
    if not pos or not neg:
        return None
    s = sum((1.0 if p > n else 0.5 if p == n else 0.0) for p in pos for n in neg)
    return s / (len(pos) * len(neg))


def vrr_a1(v):
    """VRR among attempts whose patch applied: sum V / sum A."""
    return _div(sum(r["V"] for r in v if r["A"] == 1), sum(r["A"] for r in v))


# Fixed outcome categories (mutually exclusive, every attempt in exactly one).
CATEGORIES = ["infrastructure (incomplete)", "no valid answer", "patch does not apply",
              "functional and security tests fail", "only functional tests fail",
              "only security tests fail", "verified repair"]


def category(r: Dict) -> str:
    if r["eval_status"] != "complete":
        return CATEGORIES[0]
    if r["generation_status"] != "ok":
        return CATEGORIES[1]
    if r["A"] == 0:
        return CATEGORIES[2]
    if r["F"] == 0 and r["S"] == 0:
        return CATEGORIES[3]
    if r["F"] == 0:
        return CATEGORIES[4]
    if r["S"] == 0:
        return CATEGORIES[5]
    return CATEGORIES[6]


def mean_latency_s(v):
    lat = [r["latency_ms"] for r in v if r["latency_ms"] is not None]
    return float(np.mean(lat)) / 1000 if lat else None


def lat_by_vuln(rows: List[Dict]) -> Dict[str, List[Dict]]:
    out: Dict[str, List[Dict]] = {}
    for r in rows:
        if r["latency_ms"] is not None:
            out.setdefault(r["vuln_id"], []).append(r)
    return out


METRICS: Dict[str, Callable] = {
    "VRR": vrr, "FAR": far, "CR": cr, "FAR_always_claim": baseline, "Precision": precision,
    "FAR_given_A1": far_a1, "Brier": brier, "ECE": ece, "AUROC": auroc,
}


# ---------- bootstrap over vulnerabilities ----------

def bootstrap(valid_by_vuln: Dict[str, List[Dict]], fn: Callable, B: int, rng) -> Dict:
    vulns = sorted(valid_by_vuln)
    if not vulns:
        return {"ci_low": None, "ci_high": None, "undefined_resamples": B}
    vals, undefined = [], 0
    for _ in range(B):
        pick = rng.integers(0, len(vulns), len(vulns))
        sample = [r for i in pick for r in valid_by_vuln[vulns[i]]]
        x = fn(sample)
        if x is None:
            undefined += 1
        else:
            vals.append(x)
    if not vals:
        return {"ci_low": None, "ci_high": None, "undefined_resamples": undefined}
    lo, hi = np.percentile(vals, [2.5, 97.5])
    return {"ci_low": float(lo), "ci_high": float(hi), "undefined_resamples": undefined}


def bootstrap_diff(a: Dict[str, List[Dict]], b: Dict[str, List[Dict]], fn, B, rng) -> Dict:
    """Model a minus model b, resampling the vulnerabilities both were run on."""
    vulns = sorted(set(a) | set(b))
    point_a, point_b = fn([r for x in a.values() for r in x]), fn([r for x in b.values() for r in x])
    point = None if point_a is None or point_b is None else point_a - point_b
    vals, undefined = [], 0
    for _ in range(B):
        pick = rng.integers(0, len(vulns), len(vulns))
        xa = fn([r for i in pick for r in a.get(vulns[i], [])])
        xb = fn([r for i in pick for r in b.get(vulns[i], [])])
        if xa is None or xb is None:
            undefined += 1
        else:
            vals.append(xa - xb)
    ci = (None, None) if not vals else tuple(float(x) for x in np.percentile(vals, [2.5, 97.5]))
    return {"estimate": point, "ci_low": ci[0], "ci_high": ci[1], "undefined_resamples": undefined}


# ---------- outcome categories (descriptive) ----------

def outcome(r: Dict) -> str:
    if r["eval_status"] != "complete":
        return f"incomplete: {r['incomplete_reason'] or r['eval_status']}"
    if r["generation_status"] in ("parse_error", "refusal", "truncated"):
        return f"no usable answer: {r['generation_status']}"
    if r["A"] == 0:
        return "patch does not apply"
    if r["V"] == 1:
        return "verified repair"
    if r["F"] == 0 and r["S"] == 0:
        return "breaks functionality and security test fails"
    if r["F"] == 0:
        return "breaks functionality (security test passes)"
    return "security test fails (functionality preserved)"


# ---------- formatting ----------

def fmt(x: Optional[float], pct: bool = False) -> str:
    if x is None:
        return "undefined"
    return f"{100 * x:.1f}%" if pct else f"{x:.3f}"


def fmt_ci(m: Dict, pct: bool) -> str:
    est = fmt(m["estimate"], pct)
    if m["estimate"] is None:
        return est
    if m["ci_low"] is None:
        return f"{est} [CI undefined]"
    return f"{est} [{fmt(m['ci_low'], pct)}, {fmt(m['ci_high'], pct)}]"


PCT = {"VRR", "FAR", "CR", "FAR_always_claim", "Precision", "FAR_given_A1"}
LABELS = {"VRR": "VRR", "FAR": "FAR", "CR": "Claim rate (CR)",
          "FAR_always_claim": "FAR always-claim baseline (1 - VRR)",
          "Precision": "Claim precision (1 - FAR)", "FAR_given_A1": "FAR | A=1",
          "Brier": "Brier score", "ECE": "ECE (10 bins)", "AUROC": "AUROC"}


def md_table(header: List[str], rows: List[List[str]]) -> str:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(c.replace("|", "\\|") for c in r) + " |" for r in rows]
    return "\n".join(out) + "\n"


def tex_escape(s: str) -> str:
    return (s.replace("\\", "\\textbackslash{}").replace("%", "\\%").replace("_", "\\_")
             .replace("&", "\\&").replace("#", "\\#"))


def tex_table(header: List[str], rows: List[List[str]], caption: str, label: str) -> str:
    cols = "l" + "r" * (len(header) - 1)
    lines = ["\\begin{table}[ht]", "\\centering", f"\\caption{{{tex_escape(caption)}}}",
             f"\\label{{{label}}}", f"\\begin{{tabular}}{{{cols}}}", "\\hline",
             " & ".join(tex_escape(h) for h in header) + " \\\\", "\\hline"]
    lines += [" & ".join(tex_escape(c) for c in r) + " \\\\" for r in rows]
    lines += ["\\hline", "\\end{tabular}", "\\end{table}"]
    return "\n".join(lines) + "\n"


# ---------- charts ----------

def _style(ax):
    ax.set_facecolor(SURFACE)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(INK2)
    ax.tick_params(colors=INK2)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def charts(out: Path, per_model: Dict, valid: Dict[str, List[Dict]], all_rows: List[Dict]):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    agents = [a for a, _ in MODELS if a in per_model]
    names = {a: m for a, m in MODELS}

    # 1. Rates with bootstrap CIs
    keys = ["VRR", "CR", "FAR", "FAR_always_claim", "FAR_given_A1"]
    fig, ax = plt.subplots(figsize=(8, 4.2), facecolor=SURFACE)
    _style(ax)
    width = 0.36
    x = np.arange(len(keys))
    for j, a in enumerate(agents):
        for i, k in enumerate(keys):
            m = per_model[a]["metrics"][k]
            xi = x[i] + (j - (len(agents) - 1) / 2) * (width + 0.02)
            if m["estimate"] is None:
                ax.text(xi, 0.02, "undef.", ha="center", va="bottom", fontsize=7,
                        color=INK2, rotation=90)
                continue
            ax.bar(xi, 100 * m["estimate"], width, color=COLORS[a],
                   label=names[a] if i == 0 else None, zorder=2)
            if m["ci_low"] is not None:
                ax.errorbar(xi, 100 * m["estimate"],
                            yerr=[[100 * (m["estimate"] - m["ci_low"])],
                                  [100 * (m["ci_high"] - m["estimate"])]],
                            color=INK, capsize=3, linewidth=1, zorder=3)
    ax.set_xticks(x)
    ax.set_xticklabels(["VRR", "Claim rate", "FAR", "FAR always-claim\n(1 - VRR)", "FAR | A=1"],
                       color=INK)
    ax.set_ylabel("% of attempts (95% bootstrap CI)", color=INK)
    ax.set_ylim(0, 105)
    ax.legend(frameon=False, loc="lower right", bbox_to_anchor=(1.0, 1.0), ncol=len(agents))
    ax.set_title("Verified repair and false assurance by model", color=INK, loc="left")
    fig.tight_layout()
    fig.savefig(out / "fig_metrics.png", dpi=200)
    plt.close(fig)

    # 2. Reliability diagram, one panel per model (small multiples, same axes)
    fig, axes = plt.subplots(1, len(agents), figsize=(4.2 * len(agents), 4.2),
                             facecolor=SURFACE, sharey=True, squeeze=False)
    for ax, a in zip(axes[0], agents):
        _style(ax)
        ax.grid(axis="x", color=GRID, linewidth=0.8)
        ax.plot([0, 1], [0, 1], color=INK2, linewidth=1, linestyle="--", label="perfect calibration")
        w = [r for r in valid[a] if r["P"] is not None]
        xs, ys, ns = [], [], []
        for k in range(10):
            b = [r for r in w if bin_index(r["P"]) == k]
            if b:
                xs.append(sum(r["P"] for r in b) / len(b))
                ys.append(sum(r["V"] for r in b) / len(b))
                ns.append(len(b))
        ax.plot(xs, ys, color=COLORS[a], linewidth=2, zorder=3)
        ax.scatter(xs, ys, s=[30 + 12 * n for n in ns], color=COLORS[a],
                   edgecolor=SURFACE, linewidth=2, zorder=4)
        for xi, yi, n in zip(xs, ys, ns):
            ax.annotate(f"n={n}", (xi, yi), textcoords="offset points", xytext=(6, 6),
                        fontsize=7, color=INK2)
        ax.set_xlim(0, 1)
        ax.set_ylim(-0.02, 1.02)
        ax.set_xlabel("Mean confidence in bin", color=INK)
        ax.set_title(names[a], color=INK, loc="left")
    axes[0][0].set_ylabel("Fraction verified (V=1)", color=INK)
    axes[0][0].legend(frameon=False, loc="upper left", fontsize=8)
    fig.suptitle("Reliability diagram (10 confidence bins)", color=INK, x=0.02, ha="left")
    fig.tight_layout()
    fig.savefig(out / "fig_reliability.png", dpi=200)
    plt.close(fig)

    # 3. Latency per attempt (strip + median)
    fig, ax = plt.subplots(figsize=(6, 3.6), facecolor=SURFACE)
    _style(ax)
    rng = np.random.default_rng(0)
    for j, a in enumerate(agents):
        lat = [r["latency_ms"] / 1000 for r in all_rows
               if r["agent"] == a and r["latency_ms"] is not None]
        if not lat:
            continue
        ax.scatter(j + rng.uniform(-0.15, 0.15, len(lat)), lat, s=24, color=COLORS[a],
                   alpha=0.8, edgecolor=SURFACE, linewidth=1, zorder=3)
        med = float(np.median(lat))
        ax.hlines(med, j - 0.28, j + 0.28, color=INK, linewidth=2, zorder=4)
        ax.annotate(f"median {med:.0f} s", (j + 0.3, med), va="center", fontsize=8, color=INK)
    ax.set_xticks(range(len(agents)))
    ax.set_xticklabels([names[a] for a in agents], color=INK)
    ax.set_xlim(-0.6, len(agents) - 0.1)
    ax.set_ylim(bottom=0)
    ax.set_ylabel("API latency per attempt (s)", color=INK)
    ax.set_title("API latency", color=INK, loc="left")
    fig.tight_layout()
    fig.savefig(out / "fig_latency.png", dpi=200)
    plt.close(fig)


# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description="Final aggregation of the full study.")
    ap.add_argument("--runs", type=Path, default=HERE / "runs/final")
    ap.add_argument("--ids-file", type=Path, default=HERE / "results/selection_v2/selected_ids.txt")
    ap.add_argument("--selection-dir", type=Path, default=HERE / "results/selection_v2")
    ap.add_argument("--out", type=Path, default=HERE / "results/final_v2")
    ap.add_argument("--bootstrap", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=20261124)
    args = ap.parse_args()

    ids = [l.strip() for l in args.ids_file.read_text().splitlines() if l.strip()]
    rows = load_attempts(args.runs, ids)
    args.out.mkdir(parents=True, exist_ok=True)

    with open(args.out / "attempts.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) + ["outcome"])
        w.writeheader()
        for r in rows:
            w.writerow({**r, "outcome": outcome(r)})

    rng = np.random.default_rng(args.seed)
    lat_rng = np.random.default_rng(args.seed + 1)
    a1_rng = np.random.default_rng(args.seed + 2)
    per_model: Dict[str, Dict] = {}
    valid_by_agent: Dict[str, List[Dict]] = {}
    by_vuln_by_agent: Dict[str, Dict[str, List[Dict]]] = {}
    for agent, model in MODELS:
        mine = [r for r in rows if r["agent"] == agent]
        if not mine:
            continue
        valid = [r for r in mine if r["eval_status"] == "complete"]
        valid_by_agent[agent] = valid
        by_vuln: Dict[str, List[Dict]] = {}
        for r in valid:
            by_vuln.setdefault(r["vuln_id"], []).append(r)
        by_vuln_by_agent[agent] = by_vuln
        metrics = {}
        for name, fn in METRICS.items():
            metrics[name] = {"estimate": fn(valid), **bootstrap(by_vuln, fn, args.bootstrap, rng)}
        lat = [r["latency_ms"] for r in mine if r["latency_ms"] is not None]
        gen_counts: Dict[str, int] = {}
        out_counts: Dict[str, int] = {}
        for r in mine:
            gen_counts[r["generation_status"]] = gen_counts.get(r["generation_status"], 0) + 1
            o = outcome(r)
            out_counts[o] = out_counts.get(o, 0) + 1
        reasoning = [r["reasoning_tokens"] for r in mine if r["reasoning_tokens"] is not None]
        per_model[agent] = {
            "model": model,
            "N_total": len(mine), "N_valid": len(valid), "N_incomplete": len(mine) - len(valid),
            "N_vulnerabilities": len(by_vuln),
            "sum_V": sum(r["V"] for r in valid), "sum_C": sum(r["C"] for r in valid),
            "sum_FA": sum(r["FA"] for r in valid),
            "N_with_confidence": len(_with_p(valid)),
            "metrics": metrics,
            "latency_s": None if not lat else {
                "mean": float(np.mean(lat)) / 1000, "median": float(np.median(lat)) / 1000,
                "p90": float(np.percentile(lat, 90)) / 1000, "n": len(lat),
                # Separate RNG stream so adding this CI leaves the other CIs unchanged.
                "mean_ci": bootstrap(lat_by_vuln(mine), mean_latency_s, args.bootstrap,
                                     lat_rng)},
            "mean_output_tokens": float(np.mean([r["output_tokens"] for r in mine
                                                 if r["output_tokens"] is not None] or [0])),
            "mean_reasoning_tokens": float(np.mean(reasoning)) if reasoning else None,
            "generation_status_counts": gen_counts,
            "outcome_counts": out_counts,
            "outcome_categories": {c: sum(1 for r in mine if category(r) == c) for c in CATEGORIES},
            # Separate RNG stream (seed + 2) so this CI leaves the other CIs unchanged.
            "VRR_given_A1": {"estimate": vrr_a1(valid),
                             **bootstrap(by_vuln, vrr_a1, args.bootstrap, a1_rng)},
            "confidence": None if not _with_p(valid) else {
                "N_P": len(_with_p(valid)),
                "mean": float(np.mean([r["P"] for r in _with_p(valid)])),
                "min": float(min(r["P"] for r in _with_p(valid))),
                "max": float(max(r["P"] for r in _with_p(valid)))},
            "latency_min_s": min(lat) / 1000 if lat else None,
            "latency_max_s": max(lat) / 1000 if lat else None,
            "model_returned": sorted({str(r["model_returned"]) for r in mine}),
        }

    diffs = {}
    if len(by_vuln_by_agent) == 2:
        a, b = [x for x, _ in MODELS]
        for name in ("VRR", "FAR", "CR", "Brier"):
            diffs[f"{name}: {a} - {b}"] = bootstrap_diff(by_vuln_by_agent[a], by_vuln_by_agent[b],
                                                         METRICS[name], args.bootstrap, rng)

    exclusions = []
    exc_p = args.selection_dir / "exclusions_by_control.csv"
    if exc_p.exists():
        with open(exc_p, newline="") as f:
            exclusions = list(csv.DictReader(f))
    selection = {}
    sel_p = args.selection_dir / "selection.json"
    if sel_p.exists():
        s = json.loads(sel_p.read_text())
        selection = {k: s[k] for k in ("seed", "n_ok", "n_eligible", "n_excluded", "n_selected",
                                        "scan_status_counts")}
        selection["eligibility"] = s.get("eligibility")
        selection["selected"] = s.get("selected")
        selection["excluded"] = [{"cve_id": e["cve_id"], "reason": e["reason"]}
                                 for e in s.get("excluded", [])]

    summary = {"generated_at_utc": datetime.now(timezone.utc).isoformat(),
               "bootstrap": {"B": args.bootstrap, "seed": args.seed,
                             "unit": "vulnerability (all repetitions resampled together)",
                             "interval": "percentile 95%"},
               "selection": selection, "models": per_model, "differences": diffs,
               "exclusions_by_control": exclusions}
    (args.out / "metrics.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    # Main table
    agents = [a for a, _ in MODELS if a in per_model]
    header = ["Metric"] + [per_model[a]["model"] for a in agents]
    body = [["Attempts (valid / total)"] + [f"{per_model[a]['N_valid']} / {per_model[a]['N_total']}"
                                            for a in agents],
            ["Vulnerabilities"] + [str(per_model[a]["N_vulnerabilities"]) for a in agents],
            ["Sum V / Sum C / Sum FA"] + [f"{per_model[a]['sum_V']} / {per_model[a]['sum_C']} / "
                                          f"{per_model[a]['sum_FA']}" for a in agents]]
    for name in METRICS:
        body.append([LABELS[name]] + [fmt_ci(per_model[a]["metrics"][name], name in PCT)
                                      for a in agents])
    def _lat(a: str) -> str:
        ls = per_model[a]["latency_s"]
        if not ls:
            return "undefined"
        ci = ls["mean_ci"]
        ci_s = "" if ci["ci_low"] is None else f" [{ci['ci_low']:.1f}, {ci['ci_high']:.1f}]"
        return f"{ls['mean']:.1f}{ci_s} / {ls['median']:.1f} / {ls['p90']:.1f}"
    body.append(["Latency mean [95% CI] / median / p90 (s)"] + [_lat(a) for a in agents])
    def _tok(a: str) -> str:
        rt = per_model[a]["mean_reasoning_tokens"]
        rt_s = "n/a" if rt is None else f"{rt:.0f}"
        return f"{per_model[a]['mean_output_tokens']:.0f} / {rt_s}"
    body.append(["Mean output / reasoning tokens"] + [_tok(a) for a in agents])
    note = (f"95% percentile bootstrap CIs, {args.bootstrap} resamples of whole vulnerabilities "
            f"(seed {args.seed}). 'undefined' = cannot be computed (e.g. FAR with no claims, "
            f"AUROC without both verified and unverified attempts).")
    md = "# Final results\n\n" + md_table(header, body) + f"\n{note}\n"
    if diffs:
        md += "\n## Differences between models\n\n" + md_table(
            ["Difference", "Estimate [95% CI]"],
            [[k, fmt_ci(v, k.split(":")[0] in PCT)] for k, v in diffs.items()])
    (args.out / "metrics.md").write_text(md, encoding="utf-8")
    (args.out / "metrics.tex").write_text(
        tex_table(header, body, "Verified repair, false assurance and calibration by model. " + note,
                  "tab:final-metrics"), encoding="utf-8")

    # Outcomes table
    cats = sorted({o for a in agents for o in per_model[a]["outcome_counts"]})
    o_rows = [[c] + [str(per_model[a]["outcome_counts"].get(c, 0)) for a in agents] for c in cats]
    o_rows.append(["Total"] + [str(per_model[a]["N_total"]) for a in agents])
    (args.out / "outcomes.md").write_text("# Outcome of every attempt\n\n"
                                         + md_table(["Outcome"] + header[1:], o_rows), encoding="utf-8")
    (args.out / "outcomes.tex").write_text(
        tex_table(["Outcome"] + header[1:], o_rows, "Outcome of every attempt by model.",
                  "tab:final-outcomes"), encoding="utf-8")

    # Fixed outcome categories + extra descriptive statistics
    c_rows = [[c] + [str(per_model[a]["outcome_categories"][c]) for a in agents] for c in CATEGORIES]
    c_rows.append(["Total"] + [str(per_model[a]["N_total"]) for a in agents])
    extra = [["VRR | A=1"] + [fmt_ci(per_model[a]["VRR_given_A1"], True) for a in agents],
             ["N_P (attempts with a confidence)"] + [
                 str(per_model[a]["confidence"]["N_P"]) if per_model[a]["confidence"] else "0"
                 for a in agents],
             ["Confidence mean [min, max]"] + [
                 "undefined" if not per_model[a]["confidence"] else
                 f"{per_model[a]['confidence']['mean']:.3f} [{per_model[a]['confidence']['min']:.2f}, "
                 f"{per_model[a]['confidence']['max']:.2f}]" for a in agents],
             ["Latency min / max (s)"] + [
                 "undefined" if per_model[a]["latency_min_s"] is None else
                 f"{per_model[a]['latency_min_s']:.1f} / {per_model[a]['latency_max_s']:.1f}"
                 for a in agents],
             ["model_returned"] + [", ".join(per_model[a]["model_returned"]) for a in agents]]
    (args.out / "outcome_categories.md").write_text(
        "# Outcome categories\n\n" + md_table(["Category"] + header[1:], c_rows)
        + "\n# Additional statistics\n\n" + md_table(["Statistic"] + header[1:], extra)
        + f"\n{note}\n", encoding="utf-8")
    (args.out / "outcome_categories.tex").write_text(
        tex_table(["Category"] + header[1:], c_rows,
                  "Outcome category of every attempt by model (mutually exclusive).",
                  "tab:final-categories")
        + tex_table(["Statistic"] + header[1:], extra,
                    "Additional statistics by model. " + note, "tab:final-extra"),
        encoding="utf-8")

    # Exclusions table
    if exclusions:
        # Eligibility = scan OK; the only exclusion rule is a missing
        # new_code_files (no source file for the prompt).
        e_rows = [[e["cve_id"], e["reason"]] for e in selection.get("excluded", [])] or \
                 [["(none)", ""]]
        pre = (f"Scan OK: {selection.get('n_ok')}; eligible: {selection.get('n_eligible')}; "
               f"selected: {selection.get('n_selected')} (seed {selection.get('seed')}; "
               f"all eligible cases are used when there are at most 30).")
        (args.out / "exclusions.md").write_text(
            "# Scan-OK cases excluded from the pool\n\n"
            + md_table(["Case", "Reason"], e_rows) + f"\n{pre}\n", encoding="utf-8")
        (args.out / "exclusions.tex").write_text(
            tex_table(["Case", "Reason"], e_rows,
                      "Cases with scan status OK excluded from the pool. " + pre,
                      "tab:exclusions"), encoding="utf-8")

    charts(args.out, per_model, valid_by_agent, rows)
    print((args.out / "metrics.md").read_text())


if __name__ == "__main__":
    main()
