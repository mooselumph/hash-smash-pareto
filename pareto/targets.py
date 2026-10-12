"""Trusted family/round adapter. Original judge and scalar target roster stay intact."""
from functools import lru_cache
from pathlib import Path
from unittest.mock import patch
import json

from verifier.frontier_tracks import LaneTrack, ROOT
from verifier import hash_functions, blake3, keccak
from verifier.io import canonical_json_bytes, sha256_bytes
from verifier.errors import VerificationError
from scripts.reference_operation_costs import Word
from pareto.scoring import evaluation_policies, objectives, policy_definition

FAMILIES = {
    'sha256': ('sha256', 1, 64),
    'sha3-256': ('sha3_256', 1, 24),
    'blake3': ('blake3', 1, 7),
    'poseidon': ('poseidon-orchard', 0, 56),
}


@lru_cache(maxsize=None)
def reference_cost(family, rounds):
    # Exactly the original trusted operation counter for existing hashes.
    Word.operations = 0
    if family == 'sha256':
        with patch.object(hash_functions.struct, 'unpack', return_value=tuple(Word(i) for i in range(16))):
            hash_functions._compress('sha256', tuple(Word(x) for x in hash_functions.IV['sha256']), bytes(64), rounds)
    elif family == 'sha3-256':
        keccak._permute_lanes([Word(i) for i in range(25)], 64, rounds)
    elif family == 'blake3':
        blake3._compress(tuple(Word(x) for x in blake3.IV), tuple(Word(i) for i in range(16)), Word(0), Word(64), Word(11), rounds)
    else:
        # Field-RAM: full round = 18 multiplications + 9 additions;
        # partial = 12 multiplications + 9 additions. x^5 uses three multiplications.
        return 8 * 27 + rounds * 21
    return Word.operations


class FamilyTrack(LaneTrack):
    @property
    def family(self):
        return self.id.removesuffix('-pareto')

    @property
    def challenge_root(self):
        return ROOT / 'pareto'

    @property
    def candidate(self):
        return self.challenge_root / 'candidates' / self.family

    @property
    def profile_path(self):
        original = ROOT / 'target-profiles' / f'{self.profile_id}.json'
        return original if original.exists() else self.challenge_root / 'target-profiles' / f'{self.profile_id}.json'

    def reference_operation_cost(self, cost):
        return reference_cost(self.family, self.rounds)

    def benchmark(self):
        result = super().benchmark()
        if self.family == 'poseidon':
            model = json.loads((self.challenge_root / 'orchard-cost-v2.json').read_text())
            model['operation_weights'] = result['cost_model']['operation_weights']
            model['reference_operation_costs'] = {self.target_id: self.reference_operation_cost(model)}
            result['cost_model'] = model
        files = sorted(self.challenge_root.glob('*.py')) + [ROOT / 'scripts/pareto_pipeline.py', self.challenge_root / 'orchard-pallas-constants.json']
        files += [ROOT / name for name in (
            'scripts/scalar_scoring_policy.py', 'scripts/scalar_score_resources.py',
            'scoring-policies/hashsmash-scalar-tm-v1.json',
            'pareto/scoring-policies/hashsmash-orchard-tm-v1.json',
        )]
        # Successor-only overlay; original cost models and review meanings stay intact.
        result['scoring_policy'] = policy_definition(self.family)
        result['pareto_adapter'] = {
            'id': 'hashsmash-pareto-v1', 'family': self.family,
            'objectives': objectives(), 'policies': evaluation_policies(self.family),
            'sha256': sha256_bytes(canonical_json_bytes({str(p.relative_to(ROOT)): sha256_bytes(p.read_bytes()) for p in files})),
        }
        return result


def track_for(family, rounds):
    if family not in FAMILIES:
        raise VerificationError('unknown Pareto hash family')
    algorithm, low, high = FAMILIES[family]
    if type(rounds) is not int or not low <= rounds <= high:
        raise VerificationError(f'{family} rounds must be an integer in {low}..{high}')
    target = f'poseidon-orchard-r{rounds}' if family == 'poseidon' else f'{family}-r{rounds}'
    return FamilyTrack(id=f'{family}-pareto', algorithm=algorithm, rounds=rounds, difficulty='frontier',
                       purpose='Configurable-round Pareto collision research', lane='exploratory', target_id=target,
                       output_bits=256, nominal_security_bits=127 if family == 'poseidon' else 128,
                       selection_status='organizer_selected', boundary_role='pareto')


def validate_admission(family, admission):
    if not isinstance(admission, dict) or set(admission) != {'acceptedRoundCounts'}:
        raise ValueError('admission must contain only acceptedRoundCounts')
    counts = admission['acceptedRoundCounts']
    if not isinstance(counts, list) or len(counts) > 80:
        raise ValueError('acceptedRoundCounts must be a list of at most 80 integers')
    for count in counts:
        track_for(family, count)
    if len(set(counts)) != len(counts):
        raise ValueError('acceptedRoundCounts must not contain duplicates')
    return counts
