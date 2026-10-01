"""Paper figures (D-78), drawn from results/summary.json, never from typed numbers.

- latency_warm_medium.pdf: warm median latency against N for A, A-ind, C and
  C-batch, medium profile, log scale.
- prefix_hit_medium.pdf: warm+prefix (prefix-cache hit) median latency against
  N for B and D, medium profile, log scale.
- bytes_medium.pdf: chain bytes against N for A, A-ind and C, medium profile,
  with Q2's break-even marked.

Points are pooled medians over the three runs; the bars span the three run
medians (the pooled bootstrap CIs are degenerately narrow; BENCHMARKS.md §6).
The break-even is recomputed from the bytes rows with the report's rule and
checked against summary.json's own statement of it.

Vector PDFs, with TrueType fonts embedded and no creation date, so that the
same summary.json gives the same bytes. Colours and markers follow the arm,
as in scripts/plot.py.
"""

import re
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FuncFormatter, LogLocator, NullFormatter  # noqa: E402

sys.path.insert(0, str(Path(__file__).parent))
from plot import COLOR, MARKER  # noqa: E402

import json  # noqa: E402

NS = [1, 2, 3, 5, 10]
PROFILE = "medium"
INK, MUTED, GRID = "#0b0b0b", "#6b6a66", "#dddcd5"

plt.rcParams.update({
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "axes.edgecolor": MUTED,
    "axes.labelcolor": INK,
    "axes.grid": True,
    "grid.color": GRID,
    "grid.linewidth": 0.5,
    "xtick.color": INK,
    "ytick.color": INK,
    "text.color": INK,
    "font.family": "serif",
    "font.size": 8,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "legend.frameon": False,
    "pdf.fonttype": 42,
    "lines.linewidth": 1.2,
})
SIZE = (3.4, 2.3)  # one column of a two-column paper, inches
SAVE = {"format": "pdf", "bbox_inches": "tight", "metadata": {"CreationDate": None, "ModDate": None}}


def configurations(summary):
    out = {}
    for r in summary["configurations"]:
        k = r["key"]
        out[(k["arm"], k["state"], k["n"], k["profile"])] = r
    return out


def floor125(x):
    """The largest of 1, 2 or 5 times a power of ten that is at most x."""
    k = 10 ** len(str(int(x))) / 10 if x >= 1 else 1
    return max(m * k for m in (1, 2, 5) if m * k <= x)


def latency_series(ax, rs, arm, state, label):
    xs, ys, lo, hi = [], [], [], []
    for n in NS:
        r = rs.get((arm, state, n, PROFILE))
        if r is None:
            sys.exit(f"summary.json has no {arm} {state} N={n} {PROFILE}")
        runs = list(r["run_medians"].values())
        med = r["pooled"]["median"] / 1000
        xs.append(n)
        ys.append(med)
        lo.append(med - min(runs) / 1000)
        hi.append(max(runs) / 1000 - med)
    ax.errorbar(xs, ys, yerr=[lo, hi], color=COLOR[arm], marker=MARKER[arm], ms=4, capsize=2,
                elinewidth=0.8, label=label)
    return min(ys)


def latency_figure(summary, out, name, lines, ylabel, ncol=2):
    rs = configurations(summary)
    fig, ax = plt.subplots(figsize=SIZE)
    lowest = min(latency_series(ax, rs, arm, state, label) for arm, state, label in lines)
    ax.set_yscale("log")
    ax.set_ylim(bottom=floor125(lowest))
    # Plain-number labels at 1, 2 and 5 times each power of ten.
    ax.yaxis.set_major_locator(LogLocator(base=10, subs=(1.0, 2.0, 5.0)))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
    ax.yaxis.set_minor_formatter(NullFormatter())
    ax.set_xticks(NS)
    ax.set_xlabel("N (bodies after the session body)")
    ax.set_ylabel(ylabel)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=ncol, fontsize=7)
    fig.savefig(out / name, **SAVE)
    plt.close(fig)


def break_even(rows):
    """The report's rule: the first N at which A's and C's sizes change order."""
    a = {r["n"]: r["total_mean"] for r in rows if r["arm"].startswith("A (") and r["profile"] == PROFILE}
    c = {r["n"]: r["total_mean"] for r in rows if r["arm"].startswith("C (") and r["profile"] == PROFILE}
    sign = lambda x: (x > 0) - (x < 0)  # noqa: E731
    start = sign(a[1] - c[1])
    for n in range(1, 11):
        if sign(a[n] - c[n]) != start and a[n] != c[n]:
            return n
    return None


def bytes_figure(summary, out):
    rows = summary["bytes"]["rows"]
    n_be = break_even(rows)
    stated = next(b["break_even"] for b in summary["break_even"] if b["profile"] == PROFILE)
    m = re.match(r"N = (\d+):", stated)
    if n_be is None or m is None or int(m.group(1)) != n_be:
        sys.exit(f"break-even mismatch: recomputed {n_be}, summary.json says {stated!r}")
    fig, ax = plt.subplots(figsize=SIZE)
    for label, arm in [("A (also B, A-mt)", "A"), ("A-ind", "A-ind"), ("C (also C-batch, D)", "C")]:
        pts = sorted((r["n"], r["total_mean"]) for r in rows if r["arm"] == label and r["profile"] == PROFILE)
        if len(pts) != 10:
            sys.exit(f"summary.json has {len(pts)} bytes rows for {label} {PROFILE}, not 10")
        xs, ys = zip(*pts)
        ax.plot(xs, ys, color=COLOR[arm], marker=MARKER[arm], ms=3.5, label=arm)
    ax.axvline(n_be, color=MUTED, ls="--", lw=0.8)
    ax.annotate(f"break-even: A < C from N = {n_be}", (n_be, 0.97), xycoords=("data", "axes fraction"),
                xytext=(4, 0), textcoords="offset points", fontsize=7, va="top", color=MUTED)
    ax.set_xticks(range(1, 11))
    ax.set_ylim(bottom=0)
    ax.set_xlabel("N (bodies after the session body)")
    ax.set_ylabel("bytes per chain")
    ax.legend(loc="lower right", fontsize=7)
    fig.savefig(out / "bytes_medium.pdf", **SAVE)
    plt.close(fig)


def main():
    results = Path(sys.argv[1] if len(sys.argv) > 1 else "results")
    out = Path(sys.argv[2] if len(sys.argv) > 2 else "paper/figures")
    summary = json.loads((results / "summary.json").read_text())
    if summary.get("dry"):
        sys.exit("summary.json is a dry run's; its numbers are never reported")
    out.mkdir(parents=True, exist_ok=True)
    latency_figure(summary, out, "latency_warm_medium.pdf",
                   [("A", "warm", "A (aggregate BLS)"), ("A-ind", "warm", "A-ind (individual BLS)"),
                    ("C", "warm", "C (Ed25519)"), ("C-batch", "warm", "C-batch (Ed25519 batch)")],
                   "median latency, µs (log scale)")
    latency_figure(summary, out, "prefix_hit_medium.pdf",
                   [("B", "warm+prefix", "B (BLS; pairing and prefix caches)"),
                    ("D", "warm+prefix", "D (Ed25519; prefix cache)")],
                   "median latency of a hit, µs (log scale)", ncol=1)
    bytes_figure(summary, out)
    for f in sorted(out.glob("*.pdf")):
        print(f"paper: figures/{f.name}")


if __name__ == "__main__":
    main()
