#!/usr/bin/env python3
"""pkg_callgraph.py
Quick-and-dirty package-to-package dependency graph generator.

It scans *.java and *.kt files under a given source tree, extracts the declared
`package` name and all `import` statements, then outputs a Graphviz DOT file or
directly renders to SVG/PNG if the graphviz CLI is available.

Usage:
  python pkg_callgraph.py --src <path/to/jadx_sources> --out graph.svg
  python pkg_callgraph.py --src <path> --out graph.dot

If the output filename ends with .svg or .png we attempt to call `dot` to
render; otherwise we just emit DOT.
"""

import argparse
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

# --- regexes ---------------------------------------------------------------
PKG_RE = re.compile(r'^\s*package\s+([\w\.]+)\s*;', re.MULTILINE)
IMPORT_RE = re.compile(r'^\s*import\s+([\w\.]+)\s*;', re.MULTILINE)

# --- helpers ---------------------------------------------------------------

def _process_file(fpath: Path):
    """Helper for parallel processing of source files."""
    if fpath.suffix.lower() not in {'.java', '.kt'}:
        return None
    try:
        text = fpath.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return None
    pkg_match = PKG_RE.search(text)
    if not pkg_match:
        return None
    package = pkg_match.group(1)
    imports = set(m.group(1).rsplit('.', 1)[0] for m in IMPORT_RE.finditer(text))
    return fpath, (package, imports)


def collect_packages(src_root: Path):
    """Return dict[file_path] = (package, set(imported_packages)). Uses multithreading for speed."""
    mapping = {}
    files = list(src_root.rglob('*'))
    with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as exe:
        for result in exe.map(_process_file, files):
            if result:
                fpath, data = result
                mapping[fpath] = data
    return mapping


def build_graph(mapping):
    """Return dict[src_pkg] -> set(dest_pkg)."""
    graph = defaultdict(set)
    for _, (pkg, imports) in mapping.items():
        for imp_pkg in imports:
            if imp_pkg == pkg:
                continue
            graph[pkg].add(imp_pkg)
    return graph


def write_dot(graph, fh):
    fh.write('digraph packages {\n')
    fh.write('  rankdir=LR;\n')
    fh.write('  node [shape=box, style=filled, color="lightblue"];\n')
    for src, dests in graph.items():
        for dst in dests:
            fh.write(f'  "{src}" -> "{dst}";\n')
    fh.write('}\n')


def main():
    ap = argparse.ArgumentParser(description='Generate package dependency graph')
    ap.add_argument('--src', required=True, help='Path to root of Java/Kotlin sources')
    ap.add_argument('--out', required=True, help='Output file (.dot/.svg/.png)')
    args = ap.parse_args()

    src_root = Path(args.src).expanduser().resolve()
    if not src_root.exists():
        sys.exit(f'Source path {src_root} does not exist')

    mapping = collect_packages(src_root)
    graph = build_graph(mapping)

    out_path = Path(args.out).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if out_path.suffix.lower() == '.dot':
        with out_path.open('w', encoding='utf-8') as fh:
            write_dot(graph, fh)
        print(f'Written DOT to {out_path}')
    elif out_path.suffix.lower() in {'.svg', '.png'}:
        # Write dot to temp then call graphviz
        from tempfile import NamedTemporaryFile
        with NamedTemporaryFile('w+', delete=False, suffix='.dot') as tmp:
            write_dot(graph, tmp)
            tmp_path = tmp.name
        cmd = ['dot', f'-T{out_path.suffix[1:]}', tmp_path, '-o', str(out_path)]
        try:
            subprocess.run(cmd, check=True)
            print(f'Graph rendered to {out_path}')
        finally:
            os.unlink(tmp_path)
    else:
        sys.exit('Unsupported output extension. Use .dot, .svg or .png')


if __name__ == '__main__':
    main() 