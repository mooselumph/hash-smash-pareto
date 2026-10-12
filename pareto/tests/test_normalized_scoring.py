"""Trusted offline successor projection tests; no participant or provider execution."""
from copy import deepcopy
import json
import io
from contextlib import ExitStack, redirect_stdout
import math
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pareto import scoring
from pareto.targets import FAMILIES, ROOT, track_for
from scripts import pareto_pipeline as pipeline
from scripts.scalar_scoring_policy import active_scalar_policy, scalar_score, validate_policy
from verifier.errors import VerificationError
from verifier.io import canonical_json_bytes, sha256_bytes

V5_ID = 'hashsmash-scalar-tm-v1'
V5_HASH = '65f6bd3eb8260395d5a9520ebe14be10f68efba6bf4625d9cebef2221b832c2d'
ORCHARD_ID = 'hashsmash-orchard-tm-v1'
ORCHARD_HASH = '497b0e3c33b57ab31fa79c957c22290327c50238793754184d48c93a86e363d7'
OBJECTIVES = [{'name': 'rounds', 'direction': '+'}, {'name': 'normalizedTimeMemoryLog2', 'direction': '-'}]


def metrics(family, time=80.125, memory=40.5):
    return {'costModelId': 'orchard-field-ram-v2' if family == 'poseidon' else 'collision-frontier-v5',
            'timeUnit': 'target-compressions', 'timeLog2': time, 'memoryLog2Bytes': memory}


def context(family):
    return {'policies': scoring.evaluation_policies(family), 'fields': {'scores': True, 'validity': True}}


class ProjectionTests(unittest.TestCase):
    def test_exact_858_eight_vectors(self):
        vectors = json.loads((ROOT / 'pareto/tests/approved-policy-vectors.json').read_text())
        self.assertEqual(len(vectors['cases']), 8)
        for family in FAMILIES:
            for row in vectors['cases']:
                raw = dict(row['metrics'], costModelId=metrics(family)['costModelId'])
                before = deepcopy(raw)
                self.assertEqual(scoring.normalized_score(family, raw), row['score'])
                self.assertEqual(raw, before)
                if family != 'poseidon':
                    self.assertEqual(scoring.normalized_score(family, raw), scalar_score(raw, active_scalar_policy()))

    def test_reviewed_resources_take_precedence_over_declared_and_previous_scores(self):
        for family in FAMILIES:
            raw = dict(metrics(family), declaredTimeLog2=1, declaredMemoryLog2Bytes=2,
                       rescorePreviousScore=3, normalizedTimeMemoryLog2=4,
                       reviewStatus='plausible_not_refuted', humanAccepted=False)
            before = deepcopy(raw)
            self.assertEqual(scoring.normalized_score(family, raw), 100.625)
            self.assertEqual(raw, before)

    def test_floor_fractional_and_large_finite_values(self):
        for family in FAMILIES:
            for time, memory, expected in [(12.5, 0, 12.5), (12.5, 19.999, 12.5),
                    (12.5, 20, 12.5), (12.5, 20.001, 12.501), (1e200, 1e200, 2e200),
                    (0, 1e308, 1e308)]:
                with self.subTest(family=family, time=time, memory=memory):
                    self.assertAlmostEqual(scoring.normalized_score(family, metrics(family, time, memory)), expected)

    def test_resource_errors_and_overflow_fail_closed(self):
        for family in FAMILIES:
            for key in ('timeLog2', 'memoryLog2Bytes'):
                for bad in (None, True, False, -1, '20', [], math.inf, -math.inf, math.nan, 10**1000):
                    raw = metrics(family); raw[key] = bad
                    with self.subTest(family=family, key=key, bad=type(bad).__name__):
                        with self.assertRaises(VerificationError): scoring.normalized_score(family, raw)
                raw = metrics(family); del raw[key]
                with self.assertRaises(VerificationError): scoring.normalized_score(family, raw)
            with self.assertRaisesRegex(VerificationError, 'finite'):
                scoring.normalized_score(family, metrics(family, 1e308, 1e308))
            for bad in (None, [], True):
                with self.assertRaises(VerificationError): scoring.normalized_score(family, bad)

    def test_policy_and_units_stay_separate(self):
        with self.assertRaisesRegex(VerificationError, 'collision-frontier-v5'):
            validate_policy(scoring.policy_definition('poseidon'))
        for family in FAMILIES:
            definition = scoring.policy_definition(family)
            expected = (ORCHARD_ID, ORCHARD_HASH) if family == 'poseidon' else (V5_ID, V5_HASH)
            self.assertEqual((definition['id'], sha256_bytes(canonical_json_bytes(definition))), expected)
            for key, value in [('timeUnit', 'seconds'), ('costModelId', 'collision-frontier-v4'),
                    ('costModelId', 'collision-frontier-v5' if family == 'poseidon' else 'orchard-field-ram-v2')]:
                raw = metrics(family); raw[key] = value
                with self.assertRaises(VerificationError): scoring.normalized_score(family, raw)

    def test_context_uses_actual_transported_policy_envelope(self):
        for family in FAMILIES:
            value = context(family)
            self.assertNotIn('objectives', value)  # Yukon currently sends only policies/fields/admission.
            self.assertEqual(value['policies']['scoring']['objectives'], OBJECTIVES)
            with patch.dict('os.environ', {'YUKON_EVALUATION': json.dumps(value)}):
                self.assertEqual(pipeline.context(family), value)
            for fields in ({'scores': True, 'validity': False}, {'scores': False, 'validity': True}):
                with patch.dict('os.environ', {'YUKON_EVALUATION': json.dumps(dict(value, fields=fields))}):
                    pipeline.context(family)
            bad_values = []
            for key in value['policies']['scoring']:
                bad = deepcopy(value); del bad['policies']['scoring'][key]; bad_values.append(bad)
                bad = deepcopy(value); bad['policies']['scoring'][key] = 'stale'; bad_values.append(bad)
            bad = deepcopy(value); bad['policies']['scoring']['objectives'] = list(reversed(OBJECTIVES)); bad_values.append(bad)
            bad = deepcopy(value); bad['policies']['scoring']['objectives'][1]['name'] = 'timeLog2'; bad_values.append(bad)
            bad = deepcopy(value); bad['policies']['scoring'] = {'id': metrics(family)['costModelId']}; bad_values.append(bad)
            bad_values.append(dict(value, objectives=[{'name': 'timeLog2', 'direction': '-'}]))
            bad_values.extend(dict(value, fields=f) for f in ({}, {'scores': True}, {'scores': 1, 'validity': True}, {'scores': False, 'validity': False}))
            for bad in bad_values:
                with patch.dict('os.environ', {'YUKON_EVALUATION': json.dumps(bad)}), self.assertRaises(ValueError):
                    pipeline.context(family)

    def test_manifest_matches_every_family_context(self):
        manifest = json.loads((ROOT / 'pareto/benchmark.json').read_text())
        for lane in manifest['tracks']:
            self.assertEqual(lane['objectives'], OBJECTIVES)
            self.assertEqual(lane['paretoPolicies'], scoring.evaluation_policies(lane['name']))
            self.assertEqual(lane['paretoPolicies']['scoring']['objectives'], lane['objectives'])



class PipelineTests(unittest.TestCase):
    def test_original_authenticated_review_and_raw_score_are_preserved(self):
        from scripts.hashsmash_pipeline import RunPaths
        from tests.helpers import candidate_fixture
        from tests.test_frontier_pipeline import fake_provider

        for family in FAMILIES:
            for request_scores in (True, False):
                with self.subTest(family=family, scores=request_scores), tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
                    root = Path(tmp); track = track_for(family, 1)
                    candidate = candidate_fixture(root, track)
                    claim_path = candidate / 'claim.json'
                    claim = json.loads(claim_path.read_bytes())
                    claim['claim'].update(time_log2=91.25, memory_log2_bytes=40.5)
                    claim_path.write_text(json.dumps(claim))
                    candidate_before = {p.relative_to(candidate): p.read_bytes() for p in candidate.rglob('*') if p.is_file()}
                    paths = RunPaths.for_track(track, state_root=root / 'pareto/.yukon', candidate=candidate)
                    value = context(family); value['fields']['scores'] = request_scores
                    stack.enter_context(patch.object(pipeline, 'ROOT', root))
                    stack.enter_context(patch.object(pipeline, 'select_track', return_value=track))
                    stack.enter_context(patch.object(pipeline.original.RunPaths, 'for_track', return_value=paths))
                    stack.enter_context(patch.dict('os.environ', {'YUKON_EVALUATION': json.dumps(value)}))
                    stack.enter_context(redirect_stdout(io.StringIO()))
                    for name in ('socket.create_connection', 'urllib.request.urlopen', 'subprocess.Popen'):
                        stack.enter_context(patch(name, side_effect=AssertionError('offline fixtures only')))
                    stack.enter_context(fake_provider())
                    self.assertEqual(pipeline.run('intake', family), 0)
                    self.assertEqual(pipeline.run('judge', family), 0)
                    review_before = {p: p.read_bytes() for p in (paths.evidence, paths.dossier, paths.aggregate)}
                    self.assertEqual(pipeline.run('score', family), 0)
                    raw = json.loads(paths.score.read_bytes())
                    result = json.loads((root / f'pareto/.yukon/scores/{family}.json').read_bytes())
                    self.assertTrue(result['valid'])
                    self.assertEqual(result['scores'], [1, 111.75] if request_scores else None)
                    self.assertEqual(raw['score'], 91.25)
                    self.assertEqual(raw['metrics']['scoreMetric'], 'timeLog2')
                    self.assertNotIn('scoringPolicyId', raw['metrics'])
                    expected = dict(raw['metrics'], **scoring.scoring_metadata(family),
                                    paretoAdapter='hashsmash-pareto-v1', familyId=family,
                                    supportedRoundCounts=list(range(FAMILIES[family][1], FAMILIES[family][2] + 1)))
                    self.assertEqual(result['metrics'], expected)
                    self.assertFalse(result['metrics']['humanAccepted'])
                    self.assertEqual(review_before, {p: p.read_bytes() for p in review_before})
                    self.assertEqual(candidate_before, {p.relative_to(candidate): p.read_bytes() for p in candidate.rglob('*') if p.is_file()})

    def test_negative_review_emits_null_with_policy_without_rewriting_judgment(self):
        from scripts.hashsmash_pipeline import RunPaths
        from tests.helpers import candidate_fixture
        from tests.test_frontier_pipeline import fake_provider

        def unevaluable(stage, review, _):
            if stage == 'lane_evaluability':
                review['obligations'][1]['status'] = 'unresolved'

        for family in FAMILIES:
            with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
                root = Path(tmp); track = track_for(family, 1)
                candidate = candidate_fixture(root, track)
                paths = RunPaths.for_track(track, state_root=root / 'pareto/.yukon', candidate=candidate)
                stack.enter_context(patch.object(pipeline, 'ROOT', root))
                stack.enter_context(patch.object(pipeline, 'select_track', return_value=track))
                stack.enter_context(patch.object(pipeline.original.RunPaths, 'for_track', return_value=paths))
                stack.enter_context(patch.dict('os.environ', {'YUKON_EVALUATION': json.dumps(context(family))}))
                stack.enter_context(redirect_stdout(io.StringIO()))
                stack.enter_context(fake_provider(unevaluable))
                for phase in ('intake', 'judge'):
                    self.assertEqual(pipeline.run(phase, family), 0)
                before = paths.dossier.read_bytes()
                with patch.object(pipeline.original, 'run_score', side_effect=AssertionError('unqualified work must not score')):
                    self.assertEqual(pipeline.run('score', family), 0)
                result = json.loads((root / f'pareto/.yukon/scores/{family}.json').read_bytes())
                self.assertFalse(result['valid']); self.assertIsNone(result['scores'])
                self.assertIn('not_evaluable', result['reason'])
                for key, value in scoring.scoring_metadata(family).items():
                    self.assertEqual(result['metrics'][key], value)
                self.assertNotIn('timeLog2', result['metrics'])
                self.assertNotIn('memoryLog2Bytes', result['metrics'])
                self.assertEqual(paths.dossier.read_bytes(), before)

    def test_stale_context_fails_before_intake_or_output(self):
        for family in FAMILIES:
            value = context(family)
            value['policies']['scoring'] = {'id': metrics(family)['costModelId']}
            with tempfile.TemporaryDirectory() as tmp, patch.object(pipeline, 'ROOT', Path(tmp)), \
                 patch.object(pipeline, 'select_track', side_effect=AssertionError('must reject context first')), \
                 patch.dict('os.environ', {'YUKON_EVALUATION': json.dumps(value)}):
                for phase in ('intake', 'judge', 'score'):
                    with self.assertRaisesRegex(ValueError, 'does not support'):
                        pipeline.run(phase, family)
                self.assertEqual(list(Path(tmp).rglob('*')), [])


class BindingTests(unittest.TestCase):
    def test_858_sources_and_fixture_are_verbatim(self):
        # SHA-256 of source bytes at #858 5f859076da4c2990622215f1c5b25ae8ef26ff04.
        expected = {
            'scripts/scalar_scoring_policy.py': 'ff445e9736647bf7743e4a01a509ee4747194275be5a416611662d622b5f23fa',
            'scripts/scalar_score_resources.py': 'e005feb38302e4e870ff768dd05f99528f74ebbe0586fd99d26f695642218ff0',
            'scoring-policies/hashsmash-scalar-tm-v1.json': '71adea5e6f62dcd03b50a830d977f4028f6e2ff742558117930e4c68f2fe1d44',
            'pareto/tests/approved-policy-vectors.json': 'de3f06cf8eb99dbf481ca0ff6021de0245711eb5530e1276d937cd8c3b049ab8',
        }
        for name, digest in expected.items():
            self.assertEqual(sha256_bytes((ROOT / name).read_bytes()), digest)

    def test_helpers_and_both_definitions_bind_only_future_family_fingerprints(self):
        from verifier.frontier_tracks import frontier_tracks
        original_read = Path.read_bytes
        legacy_before = {t.id: t.config_sha256() for t in frontier_tracks()}
        tracks = [track_for(f, 1) for f in FAMILIES]
        before = [t.config_sha256() for t in tracks]
        for name in ('pareto/scoring.py', 'scripts/pareto_pipeline.py', 'scripts/scalar_scoring_policy.py',
                     'scripts/scalar_score_resources.py', 'scoring-policies/hashsmash-scalar-tm-v1.json',
                     'pareto/scoring-policies/hashsmash-orchard-tm-v1.json'):
            def changed(path):
                # Whitespace changes implementation bytes, not mathematical identity.
                return original_read(path) + b'\n' if path == ROOT / name else original_read(path)
            with self.subTest(path=name), patch.object(Path, 'read_bytes', changed):
                self.assertTrue(all(t.config_sha256() != old for t, old in zip(tracks, before)))
                self.assertEqual({t.id: t.config_sha256() for t in frontier_tracks()}, legacy_before)

    def test_changed_policy_definition_fails_closed(self):
        from scripts import scalar_scoring_policy
        for family, path in [('sha256', scalar_scoring_policy.ACTIVE_POLICY_PATH), ('poseidon', scoring.ORCHARD_POLICY_PATH)]:
            before = Path.read_bytes
            definition = json.loads(before(path)); definition['memoryUnitBytes'] = 1024
            def changed(p):
                return canonical_json_bytes(definition) if p == path else before(p)
            with patch.object(Path, 'read_bytes', changed), self.assertRaisesRegex(VerificationError, 'pinned'):
                scoring.policy_definition(family)

    def test_all_supported_contracts_keep_original_primitive_and_reference_prices(self):
        original_cost = json.loads((ROOT / 'cost-models/collision-frontier-v5.json').read_bytes())
        orchard_cost = json.loads((ROOT / 'pareto/orchard-cost-v2.json').read_bytes())
        count = 0
        for family, (_, low, high) in FAMILIES.items():
            for rounds in range(low, high + 1):
                track = track_for(family, rounds); benchmark = track.benchmark()
                cost = benchmark['cost_model']; reference = track.reference_operation_cost(cost)
                expected_cost = dict(orchard_cost if family == 'poseidon' else original_cost)
                expected_cost['operation_weights'] = {'target_compression': 1, 'word_operation': 1 / reference}
                if family == 'poseidon':
                    self.assertEqual(reference, 216 + 21 * rounds)
                    expected_cost['reference_operation_costs'] = {track.target_id: reference}
                self.assertEqual(cost, expected_cost)
                self.assertEqual(benchmark['pareto_adapter']['objectives'], OBJECTIVES)
                self.assertEqual(benchmark['pareto_adapter']['policies'], scoring.evaluation_policies(family))
                self.assertEqual(benchmark['scoring_policy'], scoring.policy_definition(family))
                self.assertEqual(benchmark['qualification_policy']['id'], 'paired-lanes-v1')
                count += 1
        self.assertEqual(count, 152)


if __name__ == '__main__': unittest.main()
