#!/usr/bin/env python3
"""Stage one trusted Pareto artifact with the exact root-relative manifest score path."""
from pathlib import Path
import argparse
import json
import math
import shutil
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from pareto.targets import FAMILIES


def stage(family, destination):
    root = ROOT / 'pareto'
    manifest = json.loads((root / 'benchmark.json').read_text())
    track = next(t for t in manifest['tracks'] if t['name'] == family)
    score_path = Path(track['scorePath'])
    if score_path != Path(f'.yukon/scores/{family}.json') or track['mode'] != 'pareto':
        raise ValueError('unexpected Pareto score path or mode')
    source = root / score_path
    if any(p.is_symlink() for p in (source, *source.parents)):
        raise ValueError('score paths must not contain symlinks')
    value = json.loads(source.read_bytes())
    if type(value.get('valid')) is not bool:
        raise ValueError('missing validity decision')
    scores = value.get('scores')
    if scores is not None and (not isinstance(scores,list) or len(scores)!=2 or any(type(x) not in (int,float) or not math.isfinite(x) for x in scores)):
        raise ValueError('invalid score tuple')
    if not value['valid'] and not isinstance(value.get('reason'),str):
        raise ValueError('invalid candidate needs a reason')
    destination.mkdir(parents=True, exist_ok=False)
    (destination / score_path).parent.mkdir(parents=True)
    shutil.copyfile(source, destination / score_path)

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family',required=True,choices=FAMILIES)
    parser.add_argument('--destination',required=True,type=Path)
    args=parser.parse_args()
    stage(args.family,args.destination)
