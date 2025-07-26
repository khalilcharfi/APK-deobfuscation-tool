#!/usr/bin/env python3
"""ui_mapper.py
Produces a simple Markdown document that lists Android layout XML files and
which Activity / Fragment classes reference them.

The script works by:
1. Scanning layout XML files under given directories to collect layout IDs.
2. Scanning Java/Kotlin source files for patterns like:
     setContentView(R.layout.<id>)
     inflate(R.layout.<id>, ...)
3. Building a reverse index layout_id -> [class list].
4. Emitting a markdown tree to --out.

Usage:
  python ui_mapper.py --layouts "konnash_apktool_out/res/layout*" \
                      --src konnash_jadx_out/sources \
                      --out docs/ui_tree.md
"""

import argparse
import glob
import re
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import os

LAYOUT_ID_RE = re.compile(r'^\s*<layout.+?android:id="@\+id/(\w+)"', re.DOTALL)
SET_CONTENT_RE = re.compile(r'setContentView\(R\.layout\.([A-Za-z0-9_]+)\)')
INFLATE_RE = re.compile(r'inflate\(R\.layout\.([A-Za-z0-9_]+)')


def collect_layout_ids(layout_globs):
    ids = set()
    files = []
    for pattern in layout_globs:
        files.extend(glob.glob(pattern))
    for f in files:
        try:
            text = Path(f).read_text(encoding='utf-8', errors='ignore')
        except Exception:
            continue
        # Quick heuristic: take filename (without extension) as layout id
        layout_id = Path(f).stem
        ids.add(layout_id)
    return ids


def _scan_source(f: Path, src_root: Path, layout_ids):
    """Return (layout_id, class_name) pairs found in file."""
    if f.suffix.lower() not in {'.java', '.kt'}:
        return []
    try:
        text = f.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return []
    class_name = str(f.relative_to(src_root))
    hits = []
    for match in SET_CONTENT_RE.finditer(text):
        lid = match.group(1)
        if lid in layout_ids:
            hits.append((lid, class_name))
    for match in INFLATE_RE.finditer(text):
        lid = match.group(1)
        if lid in layout_ids:
            hits.append((lid, class_name))
    return hits


def map_layout_usage(src_root: Path, layout_ids):
    mapping = defaultdict(list)  # layout_id -> [classes]
    files = list(src_root.rglob('*'))
    with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as exe:
        for hits in exe.map(_scan_source, files, [src_root]*len(files), [layout_ids]*len(files)):
            for lid, cls in hits:
                mapping[lid].append(cls)
    return mapping


def write_markdown(mapping, out_path):
    with open(out_path, 'w', encoding='utf-8') as fh:
        fh.write('# UI Layout → Class Map\n\n')
        for layout, classes in sorted(mapping.items()):
            fh.write(f'## {layout}\n')
            for cls in sorted(set(classes)):
                fh.write(f'- `{cls}`\n')
            fh.write('\n')
    print(f'Markdown written to {out_path}')


def main():
    ap = argparse.ArgumentParser(description='Generate layout usage markdown')
    ap.add_argument('--layouts', required=True, nargs='+', help='Glob(s) for layout XMLs (quote to avoid shell expansion)')
    ap.add_argument('--src', required=True, help='Root of Java/Kotlin sources')
    ap.add_argument('--out', required=True, help='Output markdown file')
    args = ap.parse_args()

    layout_ids = collect_layout_ids(args.layouts)
    src_root = Path(args.src).expanduser().resolve()
    mapping = map_layout_usage(src_root, layout_ids)
    write_markdown(mapping, args.out)


if __name__ == '__main__':
    main() 