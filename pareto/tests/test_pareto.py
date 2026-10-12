import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pareto.targets import FAMILIES, ROOT, track_for, reference_cost, validate_admission
from verifier.poseidon import digest, permute, P
from verifier.errors import VerificationError
from verifier.intake import validate_candidate
from scripts.reference_operation_costs import reference_costs
from scripts import pareto_pipeline as pipeline
from scripts.hashsmash_pipeline import RunPaths
from pareto.scoring import evaluation_policies, scoring_metadata
from tests.helpers import candidate_fixture


def evaluation(family='sha256', **extra):
    return {'fields': {'scores': True, 'validity': True}, 'policies': evaluation_policies(family), **extra}


class OrchardTests(unittest.TestCase):
    def test_all_upstream_vectors(self):
        vectors=json.loads((Path(__file__).parent/'orchard-upstream-vectors.json').read_text())
        self.assertEqual(len(vectors['hash']),11)
        self.assertEqual(len(vectors['permute']),11)
        for row in vectors['hash']:
            self.assertEqual(digest(bytes.fromhex(row[0]+row[1]),56).hex(),row[2])
        for row in vectors['permute']:
            state=tuple(int.from_bytes(bytes.fromhex(h),'little') for h in row[:3])
            self.assertEqual(tuple(x.to_bytes(32,'little').hex() for x in permute(state)),tuple(row[3:]))

    def test_canonical_domain_prevents_modular_alias_collisions(self):
        for message in (b'', bytes(63),bytes(65),P.to_bytes(32,'little')+bytes(32),bytes(32)+(P+1).to_bytes(32,'little')):
            with self.assertRaises(VerificationError): digest(message,1)
        self.assertEqual(len(digest((P-1).to_bytes(32,'little')+bytes(32),0)),32)
        for bad in (-1,57,True,1.0):
            with self.assertRaises(ValueError): digest(bytes(64),bad)

    def test_reduced_rounds_retain_original_final_constants(self):
        from verifier.poseidon import parameters
        rc,mds=parameters()
        state=[0,0,1<<65]
        for index in list(range(4))+[4,5]+list(range(60,64)):
            state=[(x+c)%P for x,c in zip(state,rc[index])]
            state=[pow(x,5,P) if index<4 or index>=60 or i==0 else x for i,x in enumerate(state)]
            state=[sum(row[i]*state[i] for i in range(3))%P for row in mds]
        self.assertEqual(digest(bytes(64),2),state[0].to_bytes(32,'little'))


class AdapterTests(unittest.TestCase):
    def test_original_hash_normalization_is_identical(self):
        old=reference_costs()
        for family,rounds in [('sha256',31),('sha256',32),('sha256',37),('sha256',38),('sha3-256',5),('sha3-256',6),('blake3',1),('blake3',2)]:
            self.assertEqual(reference_cost(family,rounds),old[f'{family}-r{rounds}'])

    def test_every_future_supported_profile_is_pinned_and_usable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)
            (path/'proof.md').write_text('Organizer test draft.\n')
            (path/'certificates').mkdir()
            (path/'certificates/manifest.json').write_text('{"schema_version":2,"certificates":[]}')
            for family,(_,low,high) in FAMILIES.items():
                for rounds in range(low,high+1):
                    track=track_for(family,rounds)
                    (path/'claim.json').write_text(json.dumps(track.draft_claim()))
                    package=validate_candidate(path,track=track)
                    self.assertEqual(package['track']['rounds'],rounds)
                    self.assertGreater(track.reference_operation_cost({}),0)

    def test_admission_is_strict_and_does_not_change_target(self):
        before=track_for('sha256',39).config_sha256()
        self.assertEqual(validate_admission('sha256',{'acceptedRoundCounts':[39,40]}),[39,40])
        self.assertEqual(validate_admission('sha256',{'acceptedRoundCounts':[]}),[])
        for value in ([True],[0],[65],[37,37],['37']):
            with self.assertRaises((ValueError,VerificationError)):
                validate_admission('sha256',{'acceptedRoundCounts':value})
        self.assertEqual(before,track_for('sha256',39).config_sha256())

    def test_drafts_and_disallowed_rounds_emit_invalid_artifacts_without_judge(self):
        for family,rounds in [('sha256',37),('sha3-256',5),('blake3',1),('poseidon',0)]:
            with self.subTest(family=family), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                track=track_for(family,rounds)
                candidate=candidate_fixture(root,track,ready=False)
                paths=RunPaths.for_track(track,state_root=root/'pareto/.yukon',candidate=candidate)
                with patch.object(pipeline,'ROOT',root),patch.object(pipeline,'select_track',return_value=track),patch.object(pipeline.original.RunPaths,'for_track',return_value=paths),patch.object(pipeline.original,'run_judge',side_effect=AssertionError('draft must not call judge')),patch.dict('os.environ',{'YUKON_EVALUATION':json.dumps(evaluation(family))}):
                    for phase in ('intake','judge','score'): self.assertEqual(pipeline.run(phase,family),0)
                    result=json.loads((root/f'pareto/.yukon/scores/{family}.json').read_text())
                    self.assertFalse(result['valid']); self.assertIsNone(result['scores'])
                    for key, value in scoring_metadata(family).items():
                        self.assertEqual(result['metrics'][key], value)
                    self.assertNotIn('timeLog2', result['metrics'])
                    self.assertNotIn('memoryLog2Bytes', result['metrics'])
                    with patch.dict('os.environ',{'YUKON_EVALUATION':json.dumps(evaluation(family, admission={'acceptedRoundCounts':[]}))}):
                        for phase in ('intake','judge','score'): self.assertEqual(pipeline.run(phase,family),0)
                        self.assertIn('not accepted',json.loads((root/f'pareto/.yukon/scores/{family}.json').read_text())['reason'])

    def test_unknown_policy_is_an_execution_failure(self):
        with patch.dict('os.environ', {'YUKON_EVALUATION': json.dumps(evaluation(policies={'scoring': {'id': 'future'}, 'validity': None}))}):
            with self.assertRaisesRegex(ValueError, 'does not support'):
                pipeline.context('sha256')

    def test_orchard_v1_evaluation_cannot_run_on_v2_source(self):
        stale = evaluation('poseidon')
        stale['policies']['scoring']['id'] = 'orchard-field-ram-v1'
        with patch.dict('os.environ', {'YUKON_EVALUATION': json.dumps(stale)}):
            with self.assertRaisesRegex(ValueError, 'does not support'):
                pipeline.context('poseidon')

    def test_algebraic_policy_is_bound_to_orchard_evidence_only(self):
        from scripts.export_review_packet import build_packet
        from tests.helpers import candidate_fixture

        track = track_for('poseidon', 2)
        policy_path = ROOT / 'pareto/orchard-cost-v2.json'
        actual_read = Path.read_text
        altered = json.loads(actual_read(policy_path))
        altered['algebraic_estimates']['matrix_multiplication_exponent'] = 2
        other = track_for('blake3', 3)
        other_before = other.config_sha256()
        def read(path, *args, **kwargs):
            return json.dumps(altered) if path == policy_path else actual_read(path, *args, **kwargs)
        with tempfile.TemporaryDirectory() as tmp:
            candidate = candidate_fixture(Path(tmp), track)
            before = build_packet(track, candidate=candidate)
            with patch.object(Path, 'read_text', read):
                after = build_packet(track, candidate=candidate)
                self.assertEqual(other.config_sha256(), other_before)
            self.assertNotEqual(before['binding']['target_config_sha256'], after['binding']['target_config_sha256'])
            self.assertEqual(before['binding']['package_sha256'], after['binding']['package_sha256'])
            self.assertEqual(before['roles'], after['roles'])

    def test_candidate_round_selection_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); candidate=root/'pareto/candidates/sha256';candidate.mkdir(parents=True)
            (candidate/'claim.json').symlink_to(ROOT/'pareto/candidates/sha256/claim.json')
            with patch.object(pipeline,'ROOT',root),self.assertRaises(VerificationError):pipeline.select_track('sha256')

    def test_transport_preserves_original_reviewed_cost(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);track=track_for('sha256',39);paths=RunPaths.for_track(track,state_root=root/'pareto/.yukon')
            paths.work.mkdir(parents=True)
            (paths.work/'pareto-outcome.json').write_text('{"intake":"passed"}')
            def scored(_):
                paths.score.parent.mkdir(parents=True)
                paths.score.write_text(json.dumps({'score':91.25,'metrics':{'rounds':39,'timeLog2':91.25,'memoryLog2Bytes':40.5,'costModelId':'collision-frontier-v5','timeUnit':'target-compressions'}}))
                return 0
            with patch.object(pipeline,'ROOT',root),patch.object(pipeline,'select_track',return_value=track),patch.object(pipeline.original.RunPaths,'for_track',return_value=paths),patch.object(pipeline.original,'run_score',side_effect=scored) as score,patch.dict('os.environ',{'YUKON_EVALUATION':json.dumps(evaluation())}):
                pipeline.run('score','sha256')
                score.assert_called_once_with(paths)
                result=json.loads((root/'pareto/.yukon/scores/sha256.json').read_text())
                self.assertEqual(result['scores'],[39,111.75]);self.assertEqual(result['metrics']['memoryLog2Bytes'],40.5)

if __name__=='__main__': unittest.main()
