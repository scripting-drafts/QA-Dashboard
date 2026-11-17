#!/usr/bin/env python3
"""Generate Windows, macOS, and Linux icons from the 512px brand mark."""
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "assets" / "qa-dashboard-light-512.png"
OUT = ROOT / "build"

OUT.mkdir(exist_ok=True)
(OUT / "icons").mkdir(exist_ok=True)

source = Image.open(SRC).convert("RGBA")
source.save(OUT / "icon.png")
source.save(OUT / "icon.ico", format="ICO",
            sizes=[(16, 16), (24, 24), (32, 32), (48, 48),
                   (64, 64), (128, 128), (256, 256)])
source.save(OUT / "icon.icns", format="ICNS")
source.save(OUT / "icons" / "512x512.png")
for size in (16, 24, 32, 48, 64, 128, 256):
    source.resize((size, size), Image.LANCZOS).save(
        OUT / "icons" / f"{size}x{size}.png")
print(f"wrote {OUT}")
