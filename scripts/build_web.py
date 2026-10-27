#!/usr/bin/env python3
"""Package only public demo assets and the explicitly allowlisted run records."""
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'target/web'
if OUT.exists():
    shutil.rmtree(OUT)
OUT.mkdir(parents=True)
for name in ('index.html', 'styles.css', 'app.mjs', 'report.mjs', 'config.json'):
    shutil.copyfile(ROOT / 'web' / name, OUT / name)
shutil.copyfile(ROOT / 'docs/thumbnail.jpg', OUT / 'thumbnail.jpg')
(OUT / '.nojekyll').touch()
(OUT / 'runs').mkdir(exist_ok=True)
for name in ('fill.json', 'refund.json', 'fill.fund.tx', 'fill.spend.tx', 'refund.fund.tx', 'refund.spend.tx'):
    shutil.copyfile(ROOT / 'runs' / name, OUT / 'runs' / name)
print(f'Packaged demo at {OUT}')
