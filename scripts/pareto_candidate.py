#!/usr/bin/env python3
"""Select a round in a pristine organizer draft, then run credential-free intake checks.

Never overwrites participant work. Non-pristine candidates must already select the
requested round. This helper does not execute experiments or call any AI provider.
"""
from pathlib import Path
import argparse
import json
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from pareto.targets import FAMILIES,track_for
from scripts.pareto_pipeline import select_track
from verifier.intake import validate_candidate
from verifier.certificates import verify_certificates
from verifier.io import atomic_write_json


def prepare(family, rounds):
    selected=track_for(family,rounds)
    current=select_track(family)
    package=validate_candidate(current.candidate,track=current)
    if current.rounds != rounds:
        expected={'claim.json','proof.md','certificates/manifest.json'}
        if (package['claim'] != current.draft_claim() or {f['path'] for f in package['files']} != expected
            or (current.candidate/'proof.md').read_text() != '# Organizer draft\n\nNot a submission or qualified baseline. See ../../README.md.\n'
            or package['certificate_manifest'] != {'schema_version':2,'certificates':[]}):
            raise ValueError('candidate contains work; preserve it and prepare a separate draft with prepare_pareto_candidate.py')
        atomic_write_json(selected.candidate/'claim.json',selected.draft_claim())
    result=validate_candidate(selected.candidate,track=selected)
    verify_certificates(selected.candidate,track=selected)
    print(json.dumps({'family':family,'rounds':rounds,'state':result['submission_state'],'package_sha256':result['package_sha256']}))

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family',required=True,choices=FAMILIES)
    parser.add_argument('--rounds',required=True,type=int)
    parser.add_argument('--show-contract',action='store_true',help='Print the selected target and cost contract without changing a candidate')
    args=parser.parse_args(argv)
    if args.show_contract:
        track=track_for(args.family,args.rounds)
        contract=track.benchmark()
        print(json.dumps({"benchmark":contract,"reference_operation_cost":track.reference_operation_cost(contract["cost_model"])},indent=2))
    else:
        prepare(args.family,args.rounds)


if __name__=='__main__':
    main()
