"""Offline checks for family skill tools; no behavioral agent trial or judging."""
from contextlib import ExitStack, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import PropertyMock, patch

from pareto.targets import FamilyTrack, track_for
from scripts import export_review_packet as exporter
from scripts import pareto_pipeline, pareto_candidate
from tests.helpers import candidate_fixture
from verifier.errors import VerificationError
from verifier.io import sha256_bytes


class FamilyPacketTests(unittest.TestCase):
    def test_family_packet_preserves_exact_target_cost_and_review_roles(self):
        for family, rounds in [('sha256', 39), ('sha3-256', 7), ('blake3', 3), ('poseidon', 0), ('poseidon', 1), ('poseidon', 2), ('poseidon', 56)]:
            with self.subTest(family=family, rounds=rounds), tempfile.TemporaryDirectory() as tmp:
                track = track_for(family, rounds)
                candidate = candidate_fixture(Path(tmp), track)
                with ExitStack() as stack:
                    for name in ['subprocess.run', 'subprocess.Popen', 'urllib.request.urlopen',
                                 'socket.create_connection', 'experiments.run_experiments']:
                        stack.enter_context(patch(name, side_effect=AssertionError('no execution or network')))
                    packet = exporter.build_packet(track, candidate=candidate)
                self.assertTrue(packet['advisory_only'])
                self.assertEqual(packet['track'], family + '-pareto')
                self.assertEqual(packet['evidence']['benchmark'], track.benchmark())
                self.assertEqual(packet['binding'], exporter.evidence_binding(packet['evidence']))
                self.assertEqual(packet['binding']['target_config_sha256'], track.config_sha256())
                for stage, role in packet['roles'].items():
                    self.assertEqual(role['system_prompt'], exporter.load_system_prompt(stage, role['strategy']))
                    self.assertEqual(role['output_schema'], exporter._schema_for_stage(stage))
                if family == 'poseidon':
                    model = packet['evidence']['benchmark']['cost_model']
                    self.assertEqual(model['id'], 'orchard-field-ram-v2')
                    self.assertEqual(model['algebraic_estimates']['matrix_multiplication_exponent'], 2.8)
                    self.assertEqual(model['algebraic_estimates']['logarithm_base'], 2)
                    self.assertEqual(track.reference_operation_cost({}), 216 + 21 * rounds)

    def test_family_resolves_current_claim_and_rejects_manifest_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / 'pareto/candidates/blake3'
            candidate.mkdir(parents=True)
            (candidate / 'claim.json').write_text(json.dumps({'rounds': 3}))
            manifest = {'schemaVersion': 2, 'tracks': [{'name': 'blake3', 'mode': 'pareto',
                                                     'editablePaths': ['candidates/blake3']}]}
            path = root / 'pareto/benchmark.json'
            path.write_text(json.dumps(manifest))
            with patch.object(exporter, 'ROOT', root), patch.object(pareto_pipeline, 'ROOT', root), \
                 patch.object(FamilyTrack, 'challenge_root', new_callable=PropertyMock, return_value=root / 'pareto'):
                track = exporter.active_family('blake3')
                self.assertEqual(track.rounds, 3)
                self.assertEqual(track.candidate, candidate)
                # Round changes are read from the same candidate, not a fixed profile default.
                (candidate / 'claim.json').write_text(json.dumps({'rounds': 4}))
                self.assertEqual(exporter.active_family('blake3').rounds, 4)
                manifest['tracks'][0]['editablePaths'] = ['candidates/sha256']
                path.write_text(json.dumps(manifest))
                with self.assertRaisesRegex(VerificationError, 'candidate path'):
                    exporter.active_family('blake3')
                manifest['tracks'][0]['mode'] = 'scalar'
                path.write_text(json.dumps(manifest))
                with self.assertRaisesRegex(VerificationError, 'configured Pareto family'):
                    exporter.active_family('blake3')
                with self.assertRaisesRegex(VerificationError, 'select one hash family'):
                    exporter.active_family('../blake3')

    def test_family_cli_writes_private_bound_packet_and_preserves_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            track = track_for('blake3', 3)
            candidate = candidate_fixture(root, track)
            before = {p.relative_to(candidate).as_posix(): p.read_bytes() for p in candidate.rglob('*') if p.is_file()}
            output = root / 'packet'
            with patch.object(exporter, 'active_family', return_value=track) as selected, \
                 patch.object(FamilyTrack, 'candidate', new_callable=PropertyMock, return_value=candidate), \
                 redirect_stdout(io.StringIO()):
                self.assertEqual(exporter.main(['--family', 'blake3', '--output-dir', str(output)]), 0)
            selected.assert_called_once_with('blake3')
            self.assertEqual(before, {p.relative_to(candidate).as_posix(): p.read_bytes() for p in candidate.rglob('*') if p.is_file()})
            manifest = json.loads((output / 'manifest.json').read_text())
            for name, digest in manifest['files'].items():
                self.assertEqual(sha256_bytes((output / name).read_bytes()), digest)
            handoff = (output / 'REVIEW.md').read_text()
            self.assertIn('fresh-context, read-only subagent', handoff)
            self.assertNotIn('promotion', handoff)
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)

    def test_show_contract_works_from_challenge_directory_without_candidate_changes(self):
        repo = Path(__file__).resolve().parents[2]
        output = io.StringIO()
        with patch.object(pareto_candidate, 'prepare', side_effect=AssertionError('must not prepare a candidate')), \
             patch.object(pareto_candidate, 'validate_candidate', side_effect=AssertionError('must not read a candidate')), \
             redirect_stdout(output):
            pareto_candidate.main(['--family', 'blake3', '--rounds', '3', '--show-contract'])
        self.assertEqual(json.loads(output.getvalue())['benchmark'], track_for('blake3', 3).benchmark())
        result = subprocess.run([sys.executable, '../scripts/pareto_candidate.py', '--family', 'blake3',
                                 '--rounds', '3', '--show-contract'], cwd=repo / 'pareto',
                                check=True, capture_output=True, text=True)
        displayed = json.loads(result.stdout)
        contract = displayed['benchmark']
        self.assertEqual(contract, track_for('blake3', 3).benchmark())
        self.assertEqual(contract['target_profile']['rounds'], 3)
        self.assertEqual(displayed['reference_operation_cost'], track_for('blake3', 3).reference_operation_cost({}))
        self.assertAlmostEqual(contract['cost_model']['operation_weights']['word_operation'], 1 / displayed['reference_operation_cost'])


    def test_draft_family_is_not_exportable(self):
        with tempfile.TemporaryDirectory() as tmp:
            track = track_for('poseidon', 0)
            candidate = candidate_fixture(Path(tmp), track, ready=False)
            with self.assertRaisesRegex(VerificationError, 'draft'):
                exporter.build_packet(track, candidate=candidate)


if __name__ == '__main__':
    unittest.main()
