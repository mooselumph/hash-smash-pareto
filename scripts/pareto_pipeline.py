#!/usr/bin/env python3
"""Pareto transport around the original HashSmash judge; no participant host execution."""
from pathlib import Path
import argparse
import os
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from pareto.targets import FAMILIES, track_for, validate_admission
from pareto.scoring import evaluation_policies, normalized_score, objectives, scoring_metadata
from scripts import hashsmash_pipeline as original
from verifier.constants import MAX_CLAIM_BYTES
from verifier.errors import VerificationError
from verifier.intake import _scan_candidate, _read_regular_file, validate_candidate
from verifier.io import atomic_write_json, load_json_bytes
from experiments import DEFAULT_DOCKER_IMAGE, ExperimentError, ExperimentSetupError


def select_track(family):
    candidate = ROOT / 'pareto/candidates' / family
    files = _scan_candidate(candidate)
    if 'claim.json' not in files:
        raise VerificationError('claim.json is required')
    claim = load_json_bytes(_read_regular_file(candidate / 'claim.json', files['claim.json'], MAX_CLAIM_BYTES, 'claim.json'), 'claim.json')
    if not isinstance(claim, dict):
        raise VerificationError('claim must be an object')
    return track_for(family, claim.get('rounds'))


def context(family):
    raw = os.environ.get('YUKON_EVALUATION')
    if raw is None:
        return None
    value = load_json_bytes(raw.encode('utf-8'), 'trusted YUKON_EVALUATION')
    if not isinstance(value, dict) or not isinstance(value.get('fields'), dict):
        raise ValueError('invalid trusted YUKON_EVALUATION')
    expected = evaluation_policies(family)
    if value.get('policies') != expected:
        raise ValueError('this pinned HashSmash judge does not support the requested policy versions')
    # Yukon transports objectives inside our scoring-policy envelope.
    # If a caller also supplies them at top level, disagreement is an error.
    if 'objectives' in value and value['objectives'] != objectives():
        raise ValueError('this pinned HashSmash judge does not support the requested objectives')
    fields = value['fields']
    if set(fields) != {'scores', 'validity'} or any(type(v) is not bool for v in fields.values()) or not any(fields.values()):
        raise ValueError('invalid requested Pareto fields')
    return value


def invalid(reason):
    return {'valid': False, 'scores': None, 'reason': str(reason)[:4000] or 'Candidate did not qualify'}


def run(command, family):
    root = ROOT / 'pareto/.yukon'
    work = root / 'work/tracks' / f'{family}-pareto'
    gate = work / 'pareto-outcome.json'
    output = root / 'scores' / f'{family}.json'
    evaluation = context(family)  # Malformed platform settings are infrastructure errors, not judgments.
    admission = evaluation.get('admission') if evaluation else None
    if admission is not None:
        accepted = validate_admission(family, admission)
    else:
        accepted = None  # Baselines and reorgs deliberately bypass current admission.
    if command == 'intake':
        gate.unlink(missing_ok=True)
        output.unlink(missing_ok=True)
        try:
            track = select_track(family)
            if accepted is not None and track.rounds not in accepted:
                atomic_write_json(gate, invalid(f'Round count {track.rounds} was not accepted when this submission was queued'))
                return 0
            paths = original.RunPaths.for_track(track)
            package = validate_candidate(paths.candidate, track=track)
            if package['submission_state'] == 'ready':
                manifest = package.get('experiment_manifest')
                if manifest and any(x['kind'] == 'python-message-pairs-v1' for x in manifest['experiments']):
                    subprocess.run(['docker', 'pull', '--platform', 'linux/amd64', DEFAULT_DOCKER_IMAGE], check=True)
            status = original.run_intake(paths)
            atomic_write_json(gate, invalid('Draft organizer template; not a submission') if status else {'intake': 'passed'})
        except ExperimentSetupError:
            raise
        except (VerificationError, ExperimentError) as error:
            atomic_write_json(gate, invalid(error))
        return 0
    outcome = load_json_bytes(gate.read_bytes(), str(gate))
    if command == 'judge':
        if outcome.get('valid') is False:
            return 0
        paths = original.RunPaths.for_track(select_track(family))
        status = original.run_judge(paths)
        if status == 3:
            return 3
        if status:
            # The original judge has already produced and bound the negative dossier.
            aggregate = load_json_bytes(paths.aggregate.read_bytes(), str(paths.aggregate))
            atomic_write_json(gate, invalid(f"Original HashSmash judge: {aggregate['status']}"))
        return 0
    if command == 'score':
        if outcome.get('valid') is False:
            result = outcome
        else:
            paths = original.RunPaths.for_track(select_track(family))
            original.run_score(paths)  # Revalidates the exact original dossier and cost review.
            scalar = load_json_bytes(paths.score.read_bytes(), str(paths.score))
            # Project independently verified raw bounds; never relabel an old tuple.
            projected = normalized_score(family, scalar['metrics'])
            scores = [paths.track.rounds, projected] if evaluation is None or evaluation['fields']['scores'] else None
            result = {'valid': True, 'scores': scores, 'metrics': scalar['metrics']}
        result.setdefault('metrics', {}).update(paretoAdapter='hashsmash-pareto-v1', familyId=family,
            supportedRoundCounts=list(range(FAMILIES[family][1], FAMILIES[family][2]+1)),
            **scoring_metadata(family),
            costModelId='orchard-field-ram-v2' if family == 'poseidon' else 'collision-frontier-v5',
            timeUnit='target-compressions')
        atomic_write_json(output, result)
        return 0
    raise ValueError('unknown pipeline phase')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['intake', 'judge', 'score', 'all'])
    parser.add_argument('--family', choices=FAMILIES, required=True)
    args = parser.parse_args()
    try:
        for phase in ('intake', 'judge', 'score') if args.command == 'all' else (args.command,):
            code = run(phase, args.family)
            if code:
                return code
        return 0
    except (OSError, ValueError, ExperimentSetupError, subprocess.SubprocessError) as error:
        print(f'Pareto pipeline infrastructure failure: {error}', file=sys.stderr)
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
