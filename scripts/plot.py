"""Plots for SPEC §13.8, drawn from summary.json (never from typed numbers).

- latency_warm.png: warm median latency vs N per arm, one panel per profile
- latency_warm_prefix.png: arms B and D, warm+prefix (hit) and prefix-miss
- bytes.png: chain bytes vs N per arm, one panel per profile
- throughput.png: accepted/s vs threads (Q6)
- q3_fit.png: arm A's cost-model fit, with residuals in a separate panel

Colour follows the arm in every plot (fixed categorical order, validated
with the dataviz palette checks); each series also has its own marker and a
direct end label, so identity never rests on colour alone. Dry-run plots
carry a "DRY RUN - not results" stamp.
"""

import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

# Fixed arm -> slot mapping (reference palette, light mode).
COLOR = {
    "A": "#2a78d6",
    "A-ind": "#eb6834",
    "C": "#1baf7a",
    "C-batch": "#eda100",
    "B": "#e87ba4",
    "D": "#008300",
    "E": "#4a3aa7",
    "A-mt": "#e34948",
}
MARKER = {"A": "o", "A-ind": "s", "C": "^", "C-batch": "v", "B": "D", "D": "P", "E": "X", "A-mt": "*"}
INK, INK2, MUTED, GRID, AXIS, SURFACE = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7", "#fcfcfb"
NS = [1, 2, 3, 5, 10]
PROFILES = ["small", "medium", "large"]

plt.rcParams.update({
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
    "axes.edgecolor": AXIS,
    "axes.labelcolor": INK2,
    "axes.titlecolor": INK,
    "axes.grid": True,
    "grid.color": GRID,
    "grid.linewidth": 0.6,
    "xtick.color": MUTED,
    "ytick.color": MUTED,
    "text.color": INK,
    "font.family": "sans-serif",
    "font.size": 9,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "legend.frameon": False,
})


def style(ax, dry):
    ax.set_axisbelow(True)
    if dry:
        ax.text(0.5, 0.5, "DRY RUN - not results", transform=ax.transAxes, ha="center", va="center",
                fontsize=14, color=MUTED, alpha=0.5, rotation=20)


def rows(summary):
    out = {}
    for r in summary["configurations"]:
        k = r["key"]
        out[(k["arm"], k["state"], k["n"], k["profile"])] = r["pooled"]
    return out


def series(ax, rs, arm, state, profile, label, dashed=False):
    xs, ys, lo, hi = [], [], [], []
    for n in NS:
        r = rs.get((arm, state, n, profile))
        if r:
            xs.append(n)
            ys.append(r["median"] / 1000)
            lo.append(r["median_ci"][0] / 1000)
            hi.append(r["median_ci"][1] / 1000)
    if not xs:
        return
    c = COLOR[arm]
    ax.plot(xs, ys, color=c, lw=2, ls="--" if dashed else "-", marker=MARKER[arm], ms=6,
            markeredgecolor=SURFACE, markeredgewidth=1, label=label)
    ax.fill_between(xs, lo, hi, color=c, alpha=0.15, lw=0)
    ax.annotate(label, (xs[-1], ys[-1]), xytext=(4, 0), textcoords="offset points", fontsize=7,
                color=INK2, va="center")


def latency(summary, out, dry, name, lines, title):
    rs = rows(summary)
    fig, axes = plt.subplots(1, 3, figsize=(13, 4.2))
    for ax, profile in zip(axes, PROFILES):
        for arm, state, label, dashed in lines:
            series(ax, rs, arm, state, profile, label, dashed)
        ax.set_yscale("log")
        ax.set_xticks(NS)
        ax.set_xlim(0.5, 12.5)
        ax.set_title(profile)
        ax.set_xlabel("N (bodies after the session)")
        style(ax, dry)
    axes[0].set_ylabel("median latency, µs (log scale; band = 95% CI)")
    handles, labels = axes[1].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=len(labels), bbox_to_anchor=(0.5, 1.02))
    fig.suptitle(title, y=1.08, fontsize=11)
    fig.savefig(out / name, dpi=160, bbox_inches="tight")
    plt.close(fig)


def bytes_plot(summary, out, dry):
    b = summary.get("bytes")
    if not b:
        return
    arms = [("A (also B, A-mt)", "A"), ("A-ind", "A-ind"), ("C (also C-batch, D)", "C"), ("E", "E")]
    fig, axes = plt.subplots(1, 3, figsize=(13, 4.2))
    for ax, profile in zip(axes, PROFILES):
        for label, arm in arms:
            pts = sorted((r["n"], r["total_mean"]) for r in b["rows"]
                         if r["arm"] == label and r["profile"] == profile)
            if not pts:
                continue
            xs, ys = zip(*pts)
            ax.plot(xs, ys, color=COLOR[arm], lw=2, marker=MARKER[arm], ms=6,
                    markeredgecolor=SURFACE, markeredgewidth=1, label=label)
            ax.annotate(arm, (xs[-1], ys[-1]), xytext=(4, 0), textcoords="offset points", fontsize=7,
                        color=INK2, va="center")
        ax.set_xticks(NS)
        ax.set_xlim(0.5, 11.5)
        ax.set_ylim(bottom=0)
        ax.set_title(profile)
        ax.set_xlabel("N")
        style(ax, dry)
    axes[0].set_ylabel("bytes per chain (mean)")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=len(labels), bbox_to_anchor=(0.5, 1.02))
    fig.suptitle("Q2: bytes on the wire", y=1.08, fontsize=11)
    fig.savefig(out / "bytes.png", dpi=160, bbox_inches="tight")
    plt.close(fig)


def throughput_plot(summary, out, dry):
    tp = summary.get("throughput") or []
    if not tp:
        return
    fig, ax = plt.subplots(figsize=(7, 4.2))
    for arm in ["A", "B", "C", "D"]:
        pts = sorted((r["threads"], r["median"]) for r in tp if r["arm"] == arm)
        if not pts:
            continue
        xs, ys = zip(*pts)
        ax.plot(xs, ys, color=COLOR[arm], lw=2, ls="--" if arm in ("B", "D") else "-",
                marker=MARKER[arm], ms=6, markeredgecolor=SURFACE, markeredgewidth=1, label=arm)
        ax.annotate(arm, (xs[-1], ys[-1]), xytext=(4, 0), textcoords="offset points", fontsize=7,
                    color=INK2, va="center")
    ax.axvspan(10.5, 14.5, color=GRID, alpha=0.5, lw=0)
    ax.text(12.5, ax.get_ylim()[0], "includes\nefficiency cores", ha="center", va="bottom", fontsize=7, color=MUTED)
    ax.set_yscale("log")
    ax.set_xticks([1, 2, 4, 8, 10, 14])
    ax.set_xlabel("threads")
    ax.set_ylabel("accepted verifications / s (median over runs; log scale)")
    ax.legend(loc="upper left")
    ax.set_title("Q6: throughput, medium profile, N = 3")
    style(ax, dry)
    fig.savefig(out / "throughput.png", dpi=160, bbox_inches="tight")
    plt.close(fig)


def fit_plot(summary, out, dry):
    fits = [f for f in summary.get("fits", []) if f["state"] == "warm"]
    if not fits:
        return
    fig, axes = plt.subplots(2, len(fits), figsize=(4.4 * len(fits), 5.6), sharex=True,
                             gridspec_kw={"height_ratios": [3, 1.3]}, squeeze=False)
    for i, f in enumerate(fits):
        fit = f["fit"]
        xs = fit["ns"]
        ys = [m / 1000 for m in fit["medians"]]
        top, bot = axes[0][i], axes[1][i]
        top.plot(xs, ys, color=COLOR["A"], lw=0, marker="o", ms=7, markeredgecolor=SURFACE,
                 markeredgewidth=1, label="A warm, median")
        line = [(fit["alpha"] + fit["beta"] * x) / 1000 for x in xs]
        top.plot(xs, line, color=INK2, lw=1.2, ls="--", label="α + β·N (OLS)")
        top.set_title(f"{f['profile']}: α = {fit['alpha']/1000:.1f} µs, β = {fit['beta']/1000:.1f} µs, "
                      f"R² = {fit['r2']:.4f}", fontsize=8)
        top.set_ylim(bottom=0)
        style(top, dry)
        bot.axhline(0, color=AXIS, lw=1)
        bot.plot(xs, [r / 1000 for r in fit["residuals"]], color=COLOR["A"], lw=0, marker="o", ms=5)
        bot.set_xlabel("N")
        bot.set_xticks(NS)
        style(bot, False)
    axes[0][0].set_ylabel("median latency, µs")
    axes[1][0].set_ylabel("residual, µs")
    axes[0][0].legend(loc="upper left")
    fig.suptitle("Q3: arm A's cost model (warm)", fontsize=11)
    fig.savefig(out / "q3_fit.png", dpi=160, bbox_inches="tight")
    plt.close(fig)


def main():
    results = Path(sys.argv[1] if len(sys.argv) > 1 else "results")
    summary = json.loads((results / "summary.json").read_text())
    dry = bool(summary.get("dry"))
    out = results / "plots"
    out.mkdir(parents=True, exist_ok=True)
    latency(summary, out, dry, "latency_warm.png",
            [("A", "warm", "A", False), ("A-ind", "warm", "A-ind", False), ("C", "warm", "C", False),
             ("C-batch", "warm", "C-batch", False), ("A-mt", "warm", "A-mt (supplementary)", False)],
            "Q1: warm per-invocation latency")
    latency(summary, out, dry, "latency_warm_prefix.png",
            [("B", "warm+prefix", "B hit", False), ("D", "warm+prefix", "D hit", False),
             ("B", "prefix-miss", "B miss", True), ("D", "prefix-miss", "D miss", True)],
            "Q1: arms B and D, prefix-cache hit (solid) and miss (dashed)")
    bytes_plot(summary, out, dry)
    throughput_plot(summary, out, dry)
    fit_plot(summary, out, dry)
    print(f"plots written to {out}")


if __name__ == "__main__":
    main()
