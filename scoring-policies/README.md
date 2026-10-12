# Successor time-memory projection

These definitions are used explicitly by the [Pareto adapter](../pareto/scoring.py).
The root scorer and original root manifest remain time-only in this repository.
This directory adds no scalar migration or operator tooling.

All four successor lanes maximize rounds and minimize
`normalizedTimeMemoryLog2 = timeLog2 + max(0, memoryLog2Bytes - 20)`.
Equivalently, score `log2(T * max(1, M / 1048576))`, where T is reviewed total
work in selected-round target-compression units and M is reviewed memory bytes.
One MiB or less adds zero; two MiB adds one. Fractional exponents are retained.
The calculation stays in log space and rejects nonfinite results. Missing,
negative, boolean, incompatible-model or incompatible-unit resources fail closed.
There is no separate memory objective or tie-break, and no cross-family ranking.
Raw `metrics.timeLog2` and `metrics.memoryLog2Bytes` retain their original meanings.

## Definitions and source

The three v5 families use [hashsmash-scalar-tm-v1.json](./hashsmash-scalar-tm-v1.json)
verbatim from [HashSmash PR #858](https://github.com/Layr-Labs/hash-smash/pull/858),
exact source commit `5f859076da4c2990622215f1c5b25ae8ef26ff04`.
[scalar_scoring_policy.py](../scripts/scalar_scoring_policy.py) and
[scalar_score_resources.py](../scripts/scalar_score_resources.py) are copied
verbatim, including the strict `collision-frontier-v5` resource guard.
Their inherited scalar/original-challenge names describe the source helpers;
only the successor invokes them here. The source's mathematical policy ID is
retained because the definition and source resource model are identical.

Orchard uses [hashsmash-orchard-tm-v1.json](../pareto/scoring-policies/hashsmash-orchard-tm-v1.json),
a distinct pinned definition with `sourceCostModelId: orchard-field-ram-v2`.
It changes only the score projection; [Orchard primitive prices and finite-work
rules](../pareto/orchard-cost-v2.json), including ω = 2.8 and C = 216 + 21*r,
remain unchanged. The adapter validates Orchard resources separately. It never
relabels them as v5 or relaxes the approved v5 helper. The raw cost-model JSONs'
`score_metric` and `memory_scoring` fields describe the original time-only score
builder; the explicit successor overlay defines this new Pareto projection.

Canonical definition hashing uses sorted keys, compact JSON separators, ASCII
encoding and one trailing newline, matching `verifier.io.canonical_json_bytes`.
The identity covers exactly the seven mathematical fields in each JSON, not the
transport envelope or review policy.

| Policy ID | Canonical definition SHA-256 |
| --- | --- |
| `hashsmash-scalar-tm-v1` | `65f6bd3eb8260395d5a9520ebe14be10f68efba6bf4625d9cebef2221b832c2d` |
| `hashsmash-orchard-tm-v1` | `497b0e3c33b57ab31fa79c957c22290327c50238793754184d48c93a86e363d7` |

The #858 source files and eight-vector fixture are byte-for-byte copies:

| Source path at that commit | Raw file SHA-256 |
| --- | --- |
| `scripts/scalar_scoring_policy.py` | `ff445e9736647bf7743e4a01a509ee4747194275be5a416611662d622b5f23fa` |
| `scripts/scalar_score_resources.py` | `e005feb38302e4e870ff768dd05f99528f74ebbe0586fd99d26f695642218ff0` |
| `scoring-policies/hashsmash-scalar-tm-v1.json` | `71adea5e6f62dcd03b50a830d977f4028f6e2ff742558117930e4c68f2fe1d44` |
| `tests/fixtures/scalar-scoring/approved-policy-vectors.json` | `de3f06cf8eb99dbf481ca0ff6021de0245711eb5530e1276d937cd8c3b049ab8` |

The fixture is installed at
[pareto/tests/approved-policy-vectors.json](../pareto/tests/approved-policy-vectors.json).
`FamilyTrack` binds both policy files, both copied helpers and the successor
adapter/pipeline into future configuration/evidence fingerprints. Root legacy
fingerprints and judge prompt sources are unaffected.

## Trusted evaluation contract

Each manifest track's objectives are exactly:

```json
[{"name":"rounds","direction":"+"},{"name":"normalizedTimeMemoryLog2","direction":"-"}]
```

Its `paretoPolicies.scoring` envelope contains exactly `id`, `definitionSha256`,
`scoreMetric`, `sourceCostModelId`, `timeUnit` and those ordered `objectives`.
Yukon transports that existing arbitrary-JSON policy as
`YUKON_EVALUATION.policies.scoring`, alongside `fields` and optional `admission`.
The nested objectives are transported policy metadata, not a new backend API
field. Current Yukon does not send top-level objectives. If provided by another
caller, they must also match. The full scoring and validity envelopes must match
this source's expected family contract; stale id-only/time-only contexts fail as
execution errors, including draft smoke checks. Offline checks may omit context.

After the original pipeline revalidates evidence and reviews, the adapter projects
the verified raw metrics. Output metrics always identify `scoreMetric`,
`scoringPolicyId`, `scoringPolicySha256`, `costModelId` and `timeUnit`. Qualified
scored outputs contain `[rounds, normalizedTimeMemoryLog2]`; validity-only requests
contain `scores: null`. Rejected/unscored work and invalid draft/baseline smoke
checks get the same policy metadata with `scores: null`, without fabricated
resource measurements. This introduces no new partial-contribution qualification.
Review status, evidence provenance and human-decision meanings remain unchanged.

## Activation boundary

This manifest is source for **fresh normalized initial evaluations**. Yukon fixes
objectives at registration and rejects reorgs that change their ordered array
with “import a new challenge”. A score-only reorg cannot rename `timeLog2`.
The existing dev registration remains pinned to
`8c81a39eb987a3235fa38569435474671fed5b1b`, with its original time-only objective
and evidence. No production registration or activation is implied by this patch.
No automatic transfer or reinterpretation of submissions or human decisions is
authorized. Yukon allows only one open challenge per source repository, so fresh
normalized dev registration needs an explicitly planned transition or a separate
source repository while retaining the old registration/evidence. This source
preparation performs no close/reimport operation.

UI follow-up must recognize both exact normalized identities/envelopes, validate
the projection, retain raw time independently of the second score, and separate
historical time-only and normalized policy cohorts. Existing time-only UI readers
cannot consume this source's contract. Source publication, fresh registration
and UI activation are separate operator steps. Admission-only round updates
continue to require no reorg.
