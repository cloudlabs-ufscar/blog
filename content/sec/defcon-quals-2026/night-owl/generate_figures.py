#!/usr/bin/env python3
import json
import os
from pathlib import Path

os.environ.setdefault("MPLCONFIGDIR", "/tmp/matplotlib-codex")

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


ROOT = Path(__file__).resolve().parent
WORKSPACE = Path("/workspace/challenges/night-owl")
WORK = WORKSPACE / "work"
FS_DEHOPPED = 24_000.0


def style():
    plt.rcParams.update(
        {
            "font.size": 10,
            "axes.titlesize": 12,
            "axes.labelsize": 10,
            "legend.fontsize": 8,
            "figure.titlesize": 13,
            "savefig.bbox": "tight",
            "svg.fonttype": "none",
        }
    )


def load_dehopped_urh():
    raw = np.fromfile(WORK / "lecture_capture_dehopped_lpf_urh.complex64", dtype=np.float32)
    return raw[0::2] + 1j * raw[1::2]


def load_complex_interleaved(path):
    raw = np.fromfile(path, dtype="<f4")
    raw = raw[: raw.size - (raw.size % 2)]
    return raw[0::2] + 1j * raw[1::2]


def specgram_matrix(iq, nfft=256, noverlap=128):
    step = nfft - noverlap
    window = np.hanning(nfft)
    frames = 1 + (len(iq) - nfft) // step
    out = np.empty((nfft, frames), dtype=np.float64)
    for i in range(frames):
        a = i * step
        x = iq[a : a + nfft] * window
        out[:, i] = np.abs(np.fft.fftshift(np.fft.fft(x))) ** 2
    freqs = np.fft.fftshift(np.fft.fftfreq(nfft, 1.0 / FS_DEHOPPED))
    return out, freqs


def plot_specgram_histogram():
    iq = load_dehopped_urh()
    spectrum, freqs = specgram_matrix(iq, nfft=256, noverlap=128)
    profile = spectrum.sum(axis=1)
    profile /= profile.max()
    local_peaks = [
        i
        for i in range(1, len(profile) - 1)
        if profile[i] >= profile[i - 1] and profile[i] >= profile[i + 1] and profile[i] > 0.03
    ]
    prominent = np.array(sorted(sorted(local_peaks, key=lambda i: profile[i], reverse=True)[:12]))
    spacing_note = ""
    if len(prominent) > 1:
        y_norm = freqs[prominent] / (FS_DEHOPPED / 2.0)
        diffs = np.diff(np.sort(y_norm))
        close = diffs[(0.035 <= diffs) & (diffs <= 0.060)]
        representative = float(np.median(close)) if len(close) else float(np.min(diffs))
        spacing_note = f"12 strongest occupied peaks;\nadjacent spacing examples\naround {representative:.3f} normalized units"

    fig, (ax0, ax1) = plt.subplots(
        1,
        2,
        figsize=(11.5, 5.8),
        width_ratios=(3.0, 1.15),
        sharey=True,
    )
    extent = [0, len(iq) / FS_DEHOPPED, freqs[0] / 1000.0, freqs[-1] / 1000.0]
    img = ax0.imshow(
        spectrum,
        extent=extent,
        origin="lower",
        aspect="auto",
        cmap="magma",
        norm=matplotlib.colors.LogNorm(vmin=max(np.percentile(spectrum, 40), 1e-20), vmax=np.percentile(spectrum, 99.9)),
    )
    ax0.set_title("Dehopped spectrogram, NFFT=256")
    ax0.set_xlabel("time (s)")
    ax0.set_ylabel("relative frequency (kHz)")
    ax0.set_ylim(-12, 12)
    ax0.grid(alpha=0.12)
    fig.colorbar(img, ax=ax0, pad=0.01, fraction=0.046, label="linear power")

    ax1.plot(profile, freqs / 1000.0, color="#1f5aa6", linewidth=1.4)
    if len(prominent):
        ax1.scatter(profile[prominent], freqs[prominent] / 1000.0, s=18, color="#d1495b", zorder=3, label="12 strongest peaks")
    ax1.axvspan(np.percentile(profile, 80), 1.05, color="#d1495b", alpha=0.08, label="visually salient bins")
    ax1.set_title("summed profile")
    ax1.set_xlabel("normalized power")
    ax1.set_xlim(0, 1.05)
    ax1.grid(alpha=0.25)
    ax1.legend(loc="lower right")
    if spacing_note:
        ax1.text(
            0.03,
            0.98,
            spacing_note,
            transform=ax1.transAxes,
            ha="left",
            va="top",
            fontsize=8,
            bbox={"facecolor": "white", "edgecolor": "0.75", "alpha": 0.86},
        )
    fig.suptitle("Exploratory M-FSK bin-count check")
    out = ROOT / "specgram_histogram.svg"
    fig.savefig(out)
    plt.close(fig)
    return out


def plot_optimized_32_grid():
    data = json.loads((WORK / "optimized_dehopped_frequency_grid.json").read_text())
    grid = data["best_grid"]
    rows = data["assignments"]
    times = np.array([r["time_s"] for r in rows])
    freqs = np.array([r["freq_hz"] for r in rows])
    indices = np.array([r["grid_index"] for r in rows])
    residuals = np.array([r["residual_hz"] for r in rows])

    levels = np.arange(grid["min_index"], grid["max_index"] + 1)
    grid_freqs = grid["offset_hz"] + levels * grid["step_hz"]

    fig, (ax0, ax1) = plt.subplots(2, 1, figsize=(10.5, 7.2), height_ratios=(2.5, 1.0), sharex=True)
    for f in grid_freqs:
        ax0.axhline(f / 1000.0, color="0.72", linewidth=0.55, alpha=0.55)
    sc = ax0.scatter(times, freqs / 1000.0, c=indices, cmap="tab20", s=34, edgecolor="black", linewidth=0.25)
    ax0.set_title(
        f"Best-fit 32-line grid: step={grid['step_hz']:.1f} Hz, used lines={grid['used_lines']}, RMS={grid['rms_hz']:.1f} Hz"
    )
    ax0.set_ylabel("tone offset after dehop (kHz)")
    ax0.grid(alpha=0.18)
    fig.colorbar(sc, ax=ax0, pad=0.01, fraction=0.035, label="grid index")

    ax1.axhline(0, color="black", linewidth=0.8)
    ax1.scatter(times, residuals, c=indices, cmap="tab20", s=28, edgecolor="black", linewidth=0.2)
    ax1.set_xlabel("time (s)")
    ax1.set_ylabel("residual (Hz)")
    ax1.grid(alpha=0.25)
    ax1.set_ylim(-260, 260)
    out = ROOT / "optimized_32_grid.svg"
    fig.savefig(out)
    plt.close(fig)
    return out


def plot_iq_plane():
    x = load_complex_interleaved(WORK / "excerpt_188250_12000_baseband_lpf_12ksps.complex")
    n = np.arange(len(x))

    fig, ax = plt.subplots(figsize=(8.6, 7.8))
    ax.plot(x.real, x.imag, color="0.72", linewidth=0.75, alpha=0.9, label="trajectory")
    sc = ax.scatter(x.real, x.imag, c=n, s=14, cmap="viridis", edgecolors="none", alpha=0.95)
    ax.scatter([], [], s=14, c="#440154", label="samples")
    ax.scatter([x.real[0]], [x.imag[0]], marker="o", s=70, c="lime", edgecolors="black", linewidths=0.7, label="start", zorder=4)
    ax.scatter([x.real[-1]], [x.imag[-1]], marker="o", s=70, c="red", edgecolors="black", linewidths=0.7, label="end", zorder=4)
    ax.set_xlim(-0.19, 0.19)
    ax.set_ylim(-0.19, 0.19)
    ax.set_aspect("equal", adjustable="box")
    ax.axhline(0, color="black", linewidth=0.5, alpha=0.35)
    ax.axvline(0, color="black", linewidth=0.5, alpha=0.35)
    ax.set_xlabel("I")
    ax.set_ylabel("Q")
    ax.set_title("Baseband Excerpt I/Q Plane\nLPF/resampled to 12 ksps, samples colored by time")
    ax.grid(alpha=0.22, linewidth=0.6)
    ax.legend(loc="best")
    fig.colorbar(sc, ax=ax, shrink=0.86, label="sample index")
    out = ROOT / "baseband_iq_plane.svg"
    fig.savefig(out)
    plt.close(fig)
    return out


def plot_modulation_model_summary():
    models = json.loads((WORK / "excerpt_tone_modulation_models.json").read_text())
    probs = models["aggregated_probabilities"]
    labels = [
        "no internal\nsymbol modulation",
        "PSK/IQ-state\nlike",
        "AM-like\nupper bound",
        "FSK/multi-\nfrequency",
    ]
    values = [
        probs["no_internal_symbol_modulation_constant_or_single_tone"],
        probs["psk_or_iq_state_like_internal_modulation"],
        probs["am_like_internal_modulation_upper_bound"],
        probs["fsk_or_multi_frequency_internal_modulation"],
    ]
    display = [max(v, 1e-12) for v in values]

    fig, ax = plt.subplots(figsize=(8.2, 4.4))
    bars = ax.bar(labels, display, color=["#2a9d8f", "#8d99ae", "#8d99ae", "#8d99ae"], edgecolor="black", linewidth=0.4)
    ax.set_yscale("log")
    ax.set_ylim(1e-12, 2)
    ax.set_ylabel("BIC weight, log scale")
    ax.set_title("Single-tone excerpt model comparison")
    ax.grid(axis="y", alpha=0.25)
    for bar, value in zip(bars, values):
        label = "1.0" if value > 0.999999 else f"{value:.1e}"
        ax.text(bar.get_x() + bar.get_width() / 2, max(value, 1e-12) * 1.6, label, ha="center", va="bottom", fontsize=9)
    out = ROOT / "modulation_model_summary.svg"
    fig.savefig(out)
    plt.close(fig)
    return out


def main():
    style()
    print(plot_specgram_histogram())
    print(plot_optimized_32_grid())
    print(plot_iq_plane())
    print(plot_modulation_model_summary())


if __name__ == "__main__":
    main()
