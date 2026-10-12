#!/usr/bin/env python3
"""Create an explicit draft for a selected supported round; refuses to overwrite work."""
import argparse
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from pareto.targets import FAMILIES, track_for


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family', required=True, choices=FAMILIES)
    parser.add_argument('--rounds', required=True, type=int)
    parser.add_argument('--destination', required=True, type=Path)
    args = parser.parse_args()
    track = track_for(args.family, args.rounds)
    args.destination.mkdir(parents=True, exist_ok=False)
    (args.destination / 'claim.json').write_text(json.dumps(track.draft_claim(), indent=2)+'\n')
    (args.destination / 'proof.md').write_text('# Draft collision research\n\nSupply a complete construction and total-cost argument.\n')
    (args.destination / 'certificates').mkdir()
    (args.destination / 'certificates/manifest.json').write_text('{"schema_version":2,"certificates":[]}\n')

if __name__ == '__main__':
    main()
