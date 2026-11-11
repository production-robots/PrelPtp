# Icon source

`PtpIconSource.svg` is the master artwork for `PrelPtpSetup\PrelPtp.ico`, the
icon shown on the setup exe and in Add/Remove Programs. The SVG was exported
from Visio.

## Rebuilding the icon

Requires Python 3 with Pillow and PyMuPDF:

    pip install pillow pymupdf

From this folder:

    python make_ico.py

This overwrites `..\PrelPtp.ico`. Pass a path to write somewhere else instead.
Rebuild `PrelPtpSetup` afterwards to embed the new icon.

## What the icon contains

| Sizes (px)                     | Format                          |
|--------------------------------|---------------------------------|
| 16, 20, 24, 32, 40, 48, 64, 96, 128 | 32-bit BGRA bitmap with AND mask |
| 256                            | PNG                             |

- The artwork is cropped to its content and centred on a transparent square.
- Below 48 px the strokes are drawn 1.1–1.5× thicker than in the SVG so lines
  stay at least about 1 px wide. The scale for each size is in `SIZES` in
  `make_ico.py`.
- `render.py` reads the CSS classes from the SVG's `<style>` block and writes
  them onto the elements as plain attributes, because MuPDF ignores `<style>`.
  Colour and layout changes in a new Visio export therefore come through
  without editing the scripts. Hairline outlines are widened to `MIN_STROKE`
  so they stay visible.

## Viewing the result

Visual Studio's image editor draws 32-bit icons with soft edges badly: you get
ringing and dark fringes. The file is fine. To inspect the individual sizes,
use IrfanView or GIMP. Don't save the icon from Visual Studio, because it can
lose the transparency.
