"""Build PrelPtp.ico from PtpIconSource.svg.

Usage: python make_ico.py [output.ico]    (default: ../PrelPtp.ico)
"""
import io
import struct
import sys
from pathlib import Path

from render import render

# size -> stroke scale (thicker strokes at small sizes so lines stay >= ~1px)
SIZES = {16: 1.5, 20: 1.4, 24: 1.4, 32: 1.25, 40: 1.1, 48: 1.0, 64: 1.0, 96: 1.0, 128: 1.0, 256: 1.0}

# sizes from this up are stored as PNG, which Windows accepts at any size (Vista and later);
# smaller ones as bitmaps, which are hardly bigger at those sizes and which every tool reads
PNG_FROM = 64


def bmp_entry(im):
    """32-bit BGRA DIB plus AND mask, the classic ICO entry format."""
    w, h = im.size
    header = struct.pack('<IiiHHIIiiII', 40, w, h * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    px = im.tobytes('raw', 'BGRA')
    xor = b''.join(px[y * w * 4:(y + 1) * w * 4] for y in reversed(range(h)))  # bottom-up
    # AND mask: 1 bit per pixel, rows padded to 32 bits; set where fully transparent
    stride = ((w + 31) // 32) * 4
    alpha = im.getchannel('A').tobytes()
    mask = bytearray()
    for y in reversed(range(h)):
        row = bytearray(stride)
        for x in range(w):
            if alpha[y * w + x] == 0:
                row[x // 8] |= 0x80 >> (x % 8)
        mask += row
    return header + xor + bytes(mask)


def png_entry(im):
    b = io.BytesIO()
    im.save(b, 'PNG', optimize=True)
    return b.getvalue()


def main(out):
    entries = []
    for size, scale in SIZES.items():
        im = render(size, scale)
        entries.append((size, png_entry(im) if size >= PNG_FROM else bmp_entry(im)))
    data = struct.pack('<HHH', 0, 1, len(entries))
    offset = 6 + 16 * len(entries)
    for size, blob in entries:
        s = 0 if size >= 256 else size  # 0 means 256 in the directory entry
        data += struct.pack('<BBBBHHII', s, s, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
    data += b''.join(blob for _, blob in entries)
    Path(out).write_bytes(data)
    print(f'Wrote {out} ({len(entries)} images, {len(data)} bytes)')


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / 'PrelPtp.ico')
