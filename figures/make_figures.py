import json
import os
import subprocess
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
OUT = os.path.join(ROOT, "figures")

plt.rcParams.update({
    "font.size": 8,
    "axes.labelsize": 8,
    "axes.titlesize": 8,
    "legend.fontsize": 7,
    "xtick.labelsize": 7,
    "ytick.labelsize": 7,
    "lines.linewidth": 1.2,
    "lines.markersize": 4,
    "figure.dpi": 200,
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.02,
})

OURS = ("Latch", "Latch-A")


def load(name):
    with open(os.path.join(DATA, name)) as f:
        return json.load(f)


def save(fig, name):
    eps = os.path.join(OUT, name + ".eps")
    fig.savefig(eps, format="eps")
    plt.close(fig)
    subprocess.run(["epstopdf", eps, "--outfile=" + os.path.join(OUT, name + ".pdf")],
                   check=True)


def short(n):
    return (n.replace("Sigstore/", "").replace("MTC/ML-DSA-44", "MTC")
            .replace("MTC-A/ML-DSA-44", "MTC-A").replace("MTC/ML-DSA-65", "MTC")
            .replace("MTC-A/ML-DSA-65", "MTC-A").replace("XMSS+ML-DSA", "XMSS")
            .replace("LMS+ML-DSA", "LMS"))


def fig_sizes(main):
    rows = main["1"]
    names = [short(r["method"]) for r in rows]
    bundle = [r["bundle_bytes"] for r in rows]
    logb = [r["log_bytes"] for r in rows]
    x = range(len(rows))
    fig, ax = plt.subplots(figsize=(3.4, 2.1))
    c1 = ["#c0392b" if short(r["method"]) in OURS else "#5a7fa8" for r in rows]
    c2 = ["#e8927c" if short(r["method"]) in OURS else "#a9c3dd" for r in rows]
    ax.bar([i - 0.2 for i in x], bundle, width=0.4, color=c1, label="bundle")
    ax.bar([i + 0.2 for i in x], logb, width=0.4, color=c2, label="log entry")
    ax.set_yscale("log")
    ax.set_ylabel("bytes")
    ax.set_xticks(list(x))
    ax.set_xticklabels(names, rotation=55, ha="right")
    ax.grid(axis="y", ls=":", lw=0.4)
    ax.set_ylim(top=max(bundle) * 6)
    ax.legend(frameon=False, ncol=2, loc="upper right")
    save(fig, "fig_sizes")


def fig_times(main):
    rows = main["1"]
    names = [short(r["method"]) for r in rows]
    x = range(len(rows))
    fig, ax = plt.subplots(figsize=(3.4, 2.1))
    keys = [("client_ms", "signer", "#5a7fa8"), ("service_ms", "service", "#7fb069"),
            ("verify_ms", "verifier", "#c0392b")]
    for j, (k, lab, col) in enumerate(keys):
        ax.bar([i + (j - 1) * 0.27 for i in x], [r[k] for r in rows], width=0.27,
               color=col, label=lab)
    ax.set_yscale("log")
    ax.set_ylabel("time per event (ms)")
    ax.set_xticks(list(x))
    ax.set_xticklabels(names, rotation=55, ha="right")
    ax.grid(axis="y", ls=":", lw=0.4)
    ax.set_ylim(top=max(r["service_ms"] for r in rows) * 60)
    ax.legend(frameon=False, ncol=3, loc="upper center")
    save(fig, "fig_times")


def fig_pareto(main):
    fig, ax = plt.subplots(figsize=(3.4, 2.2))
    for r in main["1"]:
        n = short(r["method"])
        ours = n in OURS
        ax.scatter(r["verify_ms"], r["bundle_bytes"], s=34 if ours else 20,
                   color="#c0392b" if ours else "#5a7fa8",
                   marker="*" if ours else "o", zorder=3)
        ax.annotate(n, (r["verify_ms"], r["bundle_bytes"]), textcoords="offset points",
                    xytext=(4, 3), fontsize=6)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("verification time (ms)")
    ax.set_ylabel("bundle size (bytes)")
    ax.grid(ls=":", lw=0.4)
    xl = ax.get_xlim()
    yl = ax.get_ylim()
    ax.set_xlim(xl[0] * 0.75, xl[1] * 3.2)
    ax.set_ylim(yl[0] * 0.7, yl[1] * 1.6)
    save(fig, "fig_pareto")


def fig_batch(sw):
    rows = sw["batch"]["latch"]
    base = sw["batch"]["sigstore"]
    fig, ax = plt.subplots(figsize=(3.4, 2.1))
    b = [r["batch"] for r in rows]
    ax.plot(b, [r["service_ms"] for r in rows], "o-", color="#c0392b", label="Latch")
    ax.axhline(base["service_ms"], ls="--", color="#5a7fa8", label="Sigstore/ML-DSA-44")
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xlabel("epoch batch size $B$")
    ax.set_ylabel("service time per event (ms)")
    ax.grid(ls=":", lw=0.4)
    ax2 = ax.twinx()
    ax2.plot(b, [r["bundle"] for r in rows], "s:", color="#7fb069", ms=3,
             label="Latch bundle")
    ax2.set_ylabel("bundle (bytes)", color="#7fb069")
    ax2.tick_params(axis="y", colors="#7fb069")
    h1, l1 = ax.get_legend_handles_labels()
    h2, l2 = ax2.get_legend_handles_labels()
    ax.legend(h1 + h2, l1 + l2, frameon=False, loc="lower left")
    save(fig, "fig_batch")


def fig_logsize(sw):
    rows = sw["logsize"]
    fig, ax = plt.subplots(figsize=(3.4, 2.1))
    e = [r["log2N"] for r in rows]
    ax.plot(e, [r["sigstore"] for r in rows], "o-", color="#5a7fa8", label="Sigstore")
    ax.plot(e, [r["mtc"] for r in rows], "^-", color="#7fb069", label="MTC")
    ax.plot(e, [r["latch"] for r in rows], "*-", color="#c0392b", label="Latch")
    ax.set_xlabel(r"$\log_2$ of log size $N$")
    ax.set_ylabel("bundle size (bytes)")
    ax.grid(ls=":", lw=0.4)
    ax.legend(frameon=False)
    save(fig, "fig_logsize")


def fig_amort(sw):
    a = sw["amortization"]
    fig, ax = plt.subplots(figsize=(3.4, 2.1))
    ks = [1, 2, 4, 8, 16, 32, 64, 128]
    for key, lab, col, mk in (("sigstore", "Sigstore", "#5a7fa8", "o"),
                              ("mtc", "MTC", "#7fb069", "^"),
                              ("latch", "Latch", "#c0392b", "*")):
        v = a[key]
        ax.plot(ks, [(v["shared"] + k * v["per"]) / 1024.0 for k in ks], mk + "-",
                color=col, label=lab)
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xlabel("artifacts verified from one epoch")
    ax.set_ylabel("total material (KiB)")
    ax.grid(ls=":", lw=0.4)
    ax.legend(frameon=False)
    save(fig, "fig_amort")


def fig_winternitz(sw):
    rows = sw["winternitz"]
    fig, ax = plt.subplots(figsize=(3.4, 2.1))
    for n, col, mk in ((16, "#c0392b", "*"), (24, "#5a7fa8", "o")):
        sel = [r for r in rows if r["n"] == n]
        sel.sort(key=lambda r: r["w"])
        ax.plot([r["verify_ms"] for r in sel], [r["bundle"] for r in sel], mk + "-",
                color=col, label=f"$n={n}$")
        for r in sel:
            ax.annotate(f"$w={r['w']}$", (r["verify_ms"], r["bundle"]),
                        textcoords="offset points", xytext=(4, 3), fontsize=6)
    ax.set_xscale("log")
    ax.set_xlabel("verification time (ms)")
    ax.set_ylabel("bundle size (bytes)")
    ax.grid(ls=":", lw=0.4)
    ax.legend(frameon=False)
    save(fig, "fig_winternitz")


def fig_service(sw):
    rows = sw["service_scaling"]
    fig, ax = plt.subplots(figsize=(3.4, 2.1))
    b = [r["batch"] for r in rows]
    ax.plot(b, [r["sigstore"] for r in rows], "o-", color="#5a7fa8", label="Sigstore")
    ax.plot(b, [r["mtc"] for r in rows], "^-", color="#7fb069", label="MTC")
    ax.plot(b, [r["latch"] for r in rows], "*-", color="#c0392b", label="Latch")
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xlabel("epoch batch size $B$")
    ax.set_ylabel("service time per event (ms)")
    ax.grid(ls=":", lw=0.4)
    ax.legend(frameon=False)
    save(fig, "fig_service")


def main():
    os.makedirs(OUT, exist_ok=True)
    m = load("main.json")
    sw = load("sweeps.json")
    fig_sizes(m)
    fig_times(m)
    fig_pareto(m)
    fig_batch(sw)
    fig_logsize(sw)
    fig_amort(sw)
    fig_winternitz(sw)
    fig_service(sw)
    print("figures written to", OUT)


if __name__ == "__main__":
    main()
