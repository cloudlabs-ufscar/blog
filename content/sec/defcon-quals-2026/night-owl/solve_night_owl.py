#!/usr/bin/env python3
import argparse
import struct
from collections import Counter
from pathlib import Path

import numpy as np


HEADER_SIZE = 4096
DEFAULT_IQ = Path("/workspace/challenges/night-owl/handout/lecture_capture.iq")


def parse_header(path):
    with open(path, "rb") as f:
        h = f.read(64)
    return {
        "magic": h[:8].rstrip(b"\0").decode("ascii", "replace"),
        "sample_rate": struct.unpack_from("<I", h, 12)[0],
        "dwell_s": struct.unpack_from("<f", h, 36)[0],
        "duration_s": struct.unpack_from("<f", h, 40)[0],
    }


def load_iq(path):
    raw = np.memmap(path, dtype="<f4", mode="r", offset=HEADER_SIZE)
    raw = raw[: raw.size - (raw.size % 2)]
    pairs = raw.reshape(-1, 2)
    return pairs[:, 0] + 1j * pairs[:, 1]


def parabolic_peak(power, idx):
    if idx <= 0 or idx >= len(power) - 1:
        return 0.0
    y0, y1, y2 = np.log(np.maximum(power[idx - 1 : idx + 2], 1e-30))
    denom = y0 - 2.0 * y1 + y2
    if abs(denom) < 1e-12:
        return 0.0
    return float(0.5 * (y0 - y2) / denom)


def dominant_freq(x, fs, nfft=8192):
    n = min(len(x), nfft)
    if n < 64:
        return 0.0, 0.0

    buf = np.zeros(nfft, dtype=np.complex128)
    buf[:n] = x[:n] * np.hanning(n)
    power = np.abs(np.fft.fftshift(np.fft.fft(buf))) ** 2

    # The capture often has a residual center line. It is not the burst tone.
    dc = nfft // 2
    power[dc - 2 : dc + 3] = np.median(power)

    freqs = np.fft.fftshift(np.fft.fftfreq(nfft, 1.0 / fs))
    idx = int(np.argmax(power))
    delta = parabolic_peak(power, idx)
    snr_db = 10.0 * np.log10((power[idx] + 1e-30) / (np.median(power) + 1e-30))
    return float(freqs[idx] + delta * (freqs[1] - freqs[0])), float(snr_db)


def detect_bursts(iq, fs):
    frame_s = 0.005
    frame_n = int(round(frame_s * fs))
    frame_count = len(iq) // frame_n
    power = np.mean(np.abs(iq[: frame_count * frame_n].reshape(frame_count, frame_n)) ** 2, axis=1)
    active = power > np.median(power) * 5.0

    bursts = []
    start = None
    for i, is_active in enumerate(active):
        if is_active and start is None:
            start = i
        if (not is_active or i == len(active) - 1) and start is not None:
            end = i if not is_active else i + 1
            if (end - start) * frame_s >= 0.015:
                bursts.append({"start_s": start * frame_s, "end_s": end * frame_s})
            start = None
    return bursts


def recover_carrier_plateaus(iq, fs, dwell_s, duration_s):
    plateaus = []
    subwindow_s = 0.050
    slot_count = int(round(duration_s / dwell_s))

    for slot in range(slot_count):
        start_s = slot * dwell_s
        end_s = (slot + 1) * dwell_s
        votes = []
        measurements = []

        t = start_s
        while t < end_s - 1e-9:
            a = int(round(t * fs))
            b = int(round(min(t + subwindow_s, end_s) * fs))
            freq_hz, snr_db = dominant_freq(iq[a:b], fs)
            rounded = int(round(freq_hz / 500.0) * 500)
            votes.append(rounded)
            measurements.append((rounded, freq_hz, snr_db))
            t += subwindow_s

        mode = Counter(votes).most_common(1)[0][0]
        chosen = [freq for rounded, freq, _ in measurements if rounded == mode]
        plateaus.append({"start_s": start_s, "end_s": end_s, "freq_hz": float(np.median(chosen)), "rounded_hz": mode})
    return plateaus


def carrier_at(plateaus, t):
    for plateau in plateaus:
        if plateau["start_s"] <= t < plateau["end_s"]:
            return plateau["freq_hz"]
    return plateaus[-1]["freq_hz"]


def estimate_burst_tone(iq, fs, burst, carrier_hz):
    start_s = burst["start_s"]
    end_s = burst["end_s"]
    duration_s = end_s - start_s

    # Skip the ramp/edge energy. The long middle section is the symbol tone.
    a = int(round((start_s + 0.20 * duration_s) * fs))
    b = int(round((end_s - 0.20 * duration_s) * fs))
    x = np.asarray(iq[a:b], dtype=np.complex128)
    if len(x) < 256:
        return None

    n = np.arange(len(x), dtype=np.float64)
    x *= np.exp(-2.0j * np.pi * carrier_hz * n / fs)
    x -= np.mean(x)
    x *= np.blackman(len(x))

    nfft = 1 << 19
    freqs = np.fft.fftshift(np.fft.fftfreq(nfft, 1.0 / fs))
    power = np.abs(np.fft.fftshift(np.fft.fft(x, n=nfft))) ** 2
    power[np.abs(freqs) < 80.0] *= 0.05

    idx = int(np.argmax(power))
    delta = parabolic_peak(power, idx)
    return float(freqs[idx] + delta * (freqs[1] - freqs[0]))


def decode_ascii_tone(freq_hz, step_hz=150.8, underscore_hz=-2250.0):
    codepoint = round(ord("_") + (freq_hz - underscore_hz) / step_hz)
    if 32 <= codepoint < 127:
        return codepoint, chr(codepoint)
    return codepoint, None


def is_message_char(ch):
    return ch == "_" or ("a" <= ch <= "z")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("iq", nargs="?", default=str(DEFAULT_IQ), help="path to the original lecture_capture.iq handout")
    args = parser.parse_args()

    header = parse_header(args.iq)
    iq = load_iq(args.iq)
    fs = float(header["sample_rate"])
    duration_s = len(iq) / fs

    bursts = detect_bursts(iq, fs)
    plateaus = recover_carrier_plateaus(iq, fs, header["dwell_s"], duration_s)

    print("decoded header:", header)
    print("recovered carrier offsets:", [p["rounded_hz"] for p in plateaus])
    print("detected bursts:", len(bursts))
    print()

    message = []
    print(f'{"idx":>3} {"time_s":>8} {"freq_hz":>9} {"code":>4}  char')
    for idx, burst in enumerate(bursts):
        mid_s = 0.5 * (burst["start_s"] + burst["end_s"])
        carrier_hz = carrier_at(plateaus, mid_s)
        freq_hz = estimate_burst_tone(iq, fs, burst, carrier_hz)
        if freq_hz is None:
            continue

        codepoint, ch = decode_ascii_tone(freq_hz)
        keep = ch is not None and is_message_char(ch)
        if keep:
            message.append(ch)

        rendered = ch if ch is not None else "."
        marker = " <= msg" if keep else ""
        print(f"{idx:3d} {mid_s:8.3f} {freq_hz:9.2f} {codepoint:4d}  {rendered:>2}{marker}")

    recovered = "".join(message)
    print()
    print("recovered_message =", recovered)
    print("FLAG =", f"bbb{{{recovered}}}")


if __name__ == "__main__":
    main()
