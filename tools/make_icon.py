#!/usr/bin/env python3
"""Generates plugin/icon.png: a shield with a magnifier, drawn without image libraries.

Kept in the repository so the icon is reproducible rather than an opaque binary blob.
"""
import struct
import zlib

SIZE = 144
BG = (31, 41, 51)
SHIELD = (79, 209, 197)
SHIELD_DARK = (45, 149, 150)
GLASS = (240, 246, 248)


def shield_contains(x, y, scale=1.0):
    """True inside a shield outline centred on the canvas."""
    cx = SIZE / 2.0
    top, bottom = SIZE * 0.16, SIZE * 0.88
    half_width = SIZE * 0.34 * scale
    height = (bottom - top) * scale
    top = cx - (cx - top) * scale
    ny = (y - top) / height
    if ny < 0.0 or ny > 1.0:
        return False
    # Straight flanks that taper to a point in the lower third.
    if ny < 0.62:
        allowed = half_width
    else:
        allowed = half_width * (1.0 - (ny - 0.62) / 0.38) ** 0.72
    return abs(x - cx) <= allowed


def rounded_square(x, y, radius=26):
    lo, hi = 0, SIZE - 1
    dx = max(lo + radius - x, x - (hi - radius), 0)
    dy = max(lo + radius - y, y - (hi - radius), 0)
    return dx * dx + dy * dy <= radius * radius


def pixel(x, y):
    if not rounded_square(x, y):
        return None  # transparent corner
    if shield_contains(x, y, 1.0) and not shield_contains(x, y, 0.82):
        return SHIELD
    if shield_contains(x, y, 0.82):
        # Magnifier: ring plus handle, over a darker shield interior.
        cx, cy, r = SIZE * 0.46, SIZE * 0.44, SIZE * 0.15
        d = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
        if abs(d - r) <= 3.2:
            return GLASS
        hx, hy = x - SIZE * 0.57, y - SIZE * 0.55
        if 0 <= hx <= SIZE * 0.16 and abs(hy - hx) <= 3.0:
            return GLASS
        return SHIELD_DARK
    return BG


rows = []
for y in range(SIZE):
    row = bytearray([0])  # filter type 0
    for x in range(SIZE):
        value = pixel(x, y)
        if value is None:
            row += bytes((0, 0, 0, 0))
        else:
            row += bytes(value) + b"\xff"
    rows.append(bytes(row))

raw = b"".join(rows)


def chunk(tag, data):
    return (struct.pack(">I", len(data)) + tag + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))


png = (b"\x89PNG\r\n\x1a\n"
       + chunk(b"IHDR", struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0))
       + chunk(b"IDAT", zlib.compress(raw, 9))
       + chunk(b"IEND", b""))

with open("plugin/icon.png", "wb") as handle:
    handle.write(png)
print("wrote plugin/icon.png (%d bytes, %dx%d)" % (len(png), SIZE, SIZE))
