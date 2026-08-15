import struct
import zlib
import os

def make_png(path, size, bg=(13, 17, 23), fg=(126, 231, 135)):
    # Dark square background (#0d1117) with a centered magnifying-glass-ish
    # green ring accent (#7ee787), matching the scanner's dark theme.
    width = height = size
    cx, cy = width / 2, height / 2
    r_outer = size * 0.28
    r_inner = size * 0.20
    handle_len = size * 0.16

    pixels = []
    for y in range(height):
        row = []
        for x in range(width):
            dx, dy = x - cx + size * 0.06, y - cy + size * 0.06
            dist = (dx * dx + dy * dy) ** 0.5
            is_ring = r_inner <= dist <= r_outer
            # handle: short diagonal segment from ring edge going down-right
            hx, hy = x - (cx + r_outer * 0.7), y - (cy + r_outer * 0.7)
            along = (hx + hy) / 1.4142
            perp = abs(hx - hy) / 1.4142
            is_handle = 0 <= along <= handle_len and perp <= max(1, size * 0.03)
            if is_ring or is_handle:
                row.append(fg)
            else:
                row.append(bg)
        pixels.append(row)

    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data +
                struct.pack(">I", zlib.crc32(tag + data) & 0xffffffff))

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw = bytearray()
    for row in pixels:
        raw.append(0)
        for (r, g, b) in row:
            raw += bytes((r, g, b))
    idat = zlib.compress(bytes(raw), 9)

    with open(path, "wb") as f:
        f.write(sig)
        f.write(chunk(b"IHDR", ihdr))
        f.write(chunk(b"IDAT", idat))
        f.write(chunk(b"IEND", b""))

out_dir = os.path.join(os.path.dirname(__file__), "icons")
os.makedirs(out_dir, exist_ok=True)
for sz in (16, 48, 128):
    make_png(os.path.join(out_dir, f"icon{sz}.png"), sz)
print("done")
