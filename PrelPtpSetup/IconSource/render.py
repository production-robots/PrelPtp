"""Render PtpIconSource.svg to a square RGBA image at a given size."""
import io
import re
from pathlib import Path

import pymupdf
from PIL import Image

SRC = Path(__file__).with_name('PtpIconSource.svg')


# Hairlines thinner than this (in SVG units) are widened to it, so outlines
# stay visible: about 1 px at 256 px. Visio exports its outlines at 0.24.
MIN_STROKE = 0.96


def styled_svg(stroke_scale=1.0):
    """Return the SVG text with its CSS classes inlined as attributes.

    MuPDF ignores <style> blocks, so each class's declarations are read from
    the SVG's own stylesheet and written onto the elements as presentation
    attributes. stroke_scale thickens every stroke, which keeps lines visible
    at small icon sizes.
    """
    svg = SRC.read_text(encoding='utf-8')
    style = re.search(r'<style.*?>(.*?)</style>', svg, flags=re.S)
    css = style.group(1).replace('<![CDATA[', '').replace(']]>', '') if style else ''
    styles = {}
    for name, body in re.findall(r'\.([\w-]+)\s*\{([^}]*)\}', css):
        attrs = []
        for decl in body.split(';'):
            if ':' not in decl:
                continue
            prop, value = (s.strip() for s in decl.split(':', 1))
            if prop == 'stroke-width':
                value = f'{max(float(value), MIN_STROKE) * stroke_scale:g}'
            attrs.append(f'{prop}="{value}"')
        styles[name] = ' '.join(attrs)
    svg = re.sub(r'<style.*?</style>', '', svg, flags=re.S)
    unknown = set(re.findall(r'class="([^"]*)"', svg)) - styles.keys()
    if unknown:
        raise ValueError(f'SVG uses classes with no style rule: {sorted(unknown)}')
    return re.sub(r'class="([^"]*)"', lambda m: styles[m.group(1)], svg)


def render(size, stroke_scale=1.0, pad=0.02):
    """Render at high resolution, crop to content, centre on a square, downsample."""
    doc = pymupdf.open(stream=styled_svg(stroke_scale).encode('utf-8'), filetype='svg')
    page = doc[0]
    zoom = 2048 / max(page.rect.width, page.rect.height)
    pix = page.get_pixmap(matrix=pymupdf.Matrix(zoom, zoom), alpha=True)
    im = Image.open(io.BytesIO(pix.tobytes('png'))).convert('RGBA')
    im = im.crop(im.getbbox())
    side = max(im.size)
    margin = int(side * pad)
    sq = Image.new('RGBA', (side + 2 * margin, side + 2 * margin), (0, 0, 0, 0))
    sq.paste(im, ((sq.width - im.width) // 2, (sq.height - im.height) // 2))
    return sq.resize((size, size), Image.LANCZOS)
