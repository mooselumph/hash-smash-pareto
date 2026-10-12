---
name: hashsmash-solver
description: Solve or improve an assigned HashSmash hash-family track with configurable round counts. Use for onboarding, exact SHA-256, SHA3-256, BLAKE3 or Orchard/Pallas target and cost interpretation, candidate preparation, mechanical checks, advisory subagent review and submission feedback. Harness maintenance, judge configuration and imports follow the builder guide instead.
---

# HashSmash solver

Work from the `pareto/` challenge directory printed by `yukon clone`, not the
Git repository root. Read the [solver contract](../../../pareto/TASK.md) before
editing. Commands and plain paths below are relative to `pareto/`, including
when this skill is loaded through a compatibility link. No earlier HashSmash
challenge or solver conversation is needed.

## Establish the assignment once

Use the supplied API environment, benchmark identity, hash family and accepted
round counts. The four track names are `sha256`, `sha3-256`, `blake3` and
`poseidon`; round count is a candidate parameter, not part of the CLI track name.
Check the live track status and `submissionAdmission.acceptedRoundCounts`.
An empty list admits no submissions. Supported profiles and manifest defaults
do not establish which rounds are currently open.

Inspect the checkout and preserve existing work. A clone-name collision is a
reason to use a fresh directory, not reset another checkout. Read `benchmark.json`
and establish the assigned entry's `editablePaths`: only `candidates/<family>/`
belongs to the solver. Setup failures do not expand the assignment into harness
or provider maintenance.

Read `schemas/claim.json`, `../docs/JUDGE_LANES.md`, and the selected target
profile. Profiles are `<family>-r<rounds>-prefix-v1.json`, with
`poseidon-orchard` as the Poseidon prefix. Look in `../target-profiles/` first,
then `target-profiles/`; use the exact profile named in the checked claim.
Read `../cost-models/collision-frontier-v5.json` for SHA-256, SHA3-256 and BLAKE3,
or `orchard-cost-v2.json` for Orchard. The runtime contract supplies the selected
round's normalization; do not reuse another round's compression price.

Use the installed `yukon-cli` skill (`yukon skill`) for authentication, cloning,
traces, history, notes and synchronization. For a linked checkout select the
assigned family and run `yukon trace status` before edits. Read published results,
review status and relevant submission notes. There is no single promoted
incumbent in this challenge: compare the round/normalized-cost frontier and preserve each
result's source and human decision. A bundled draft is not an accepted baseline.

For an explicitly local-only assignment, use the supplied checkout and state
that live admission/history were not checked. Never print or copy `.env`, request
judge-provider keys, or change repository settings to resolve a solver blocker.

## Reach mechanical readiness

For an assignment to BLAKE3 with round 3 admitted, run from `pareto/`:

```sh
yukon setup --track blake3
python3 ../scripts/pareto_candidate.py --family blake3 --rounds 3 --show-contract
python3 ../scripts/pareto_candidate.py --family blake3 --rounds 3
```

Substitute the assigned family and one admitted round count. Without Yukon,
`bash setup.sh` runs deterministic organizer tests. `--show-contract` prints the exact profile and priced cost model without
changing a candidate. The preparation helper selects a round only in a pristine organizer draft; for an existing candidate it checks
that the selected round matches. It refuses to overwrite research. Preserve work
and prepare a separate draft if changing rounds; do not change an API admission
setting yourself. Recheck the same candidate/round after edits.

The helper validates package structure and certificates. It executes no
participant experiments, calls no AI provider and establishes no qualification.
**Do not make `yukon run` part of ordinary setup:** it invokes the full local
provider-backed pipeline. Submit to Yukon for official remote evaluation.

Once oriented, briefly state the exact target, allowed path, existing evidence
and first research hypothesis, then proceed within the assignment. Do not turn
this setup report into an extra permission checkpoint.

## Develop the construction and its argument

Produce a classical ordinary-collision construction: two distinct inputs from
the selected domain with equal complete outputs. SHA-256, SHA3-256 and BLAKE3
require equality of all 256 digest bits on complete byte-string messages of bit
length below 2^64. Orchard requires equality of the entire output field element
for two distinct canonical input pairs. Near-collisions, compression-only or
free-start collisions, encoding aliases and quantum attacks do not solve these
targets.

Preserve each target's exact construction:

- **SHA-256:** standard fixed IV, message schedule, length padding and feed-forward;
  first r compression rounds on every padded block, all digest words.
- **SHA3-256:** Keccak-f[1600], rate 1088/capacity 512, zero initial state, SHA3
  suffix 0x06 and standard padding/encoding. Use the first r rounds in each
  permutation, not Keccak-p's last-round convention; output all 32 squeeze bytes.
- **BLAKE3:** standard unkeyed complete hash with fixed IV, 1024-byte chunks and
  64-byte blocks. Apply the first r rounds to every chunk, parent and root
  compression; preserve actual block lengths, counters, tree structure,
  feed-forward and CHUNK_START/CHUNK_END/PARENT/ROOT flags. Compare the first
  32 little-endian root output bytes, using root output counter zero; do not
  substitute equality of internal chaining values.
- **Orchard/Pallas:** P128Pow5T3, width 3, exponent 5, state `[nk,rho,2^65]`.
  Each input field element is canonical 32-byte little-endian and less than p.
  Keep eight full rounds (indices 0–3 and 60–63), the first r partial rounds
  starting at 4, and the pinned constants/MDS. Output the entire first field
  element in canonical encoding. This target is the fixed-length two-input
  Poseidon hash, not the complete Orchard nullifier construction.

Compare adapted papers to these definitions explicitly. Distinguish a generic
birthday construction, published research and a new hypothesis. An unsuccessful
restricted search does not prove that novel cryptanalysis is impossible.

Keep `proof.md`, `claim.json`, certificates and experiments about the same
algorithm. Incomplete work stays `submission_state: draft`; a complete package
uses `ready` and `lane: exploratory`. Do not manufacture official score files.
Use the [review checklist](references/review-checklist.md) for a complete package
or a finding rather than rereading operator guides.

Justify `claim.time_log2` as total work across all processors and success
probability at least 0.39. Charge preprocessing, randomness, failed trials,
sorting/lookups, initialization, memory accesses, recovery and amplification.
For H complete target compressions/permutations and W other priced operations,
`T = H + W/C` only when those terms cover all work. BLAKE3 includes every chunk,
parent and root compression. Obtain C from the selected round's contract.
Orchard uses its explicit field/word operation model, `C = 216 + 21*r`;
exponentiation and inversion require constituent-operation accounting.
For algebraic estimates read `ORCHARD_ACCOUNTING.md`: use ω = 2.8 where the
bound is parameterized by ω, keep justified finite coefficients and logarithmic
factors, and include setup and lower-order work. Neither `O(n^2.8)` nor an
unsupported coefficient of 1 supplies a numerical cost. Concrete algorithm
counts remain charged as counted; ω does not discount a cubic implementation.

Memory in bytes is required and reviewed. All four families maximize rounds and
minimize `normalizedTimeMemoryLog2 = timeLog2 + max(0, memoryLog2Bytes - 20)`.
The one-MiB floor means up to 1,048,576 bytes adds zero; every doubling above it
adds one to the cost axis. There is no separate memory objective or tie-break.
Keep raw time and memory in their claim fields; do not submit the combined score
as `time_log2`. Read [the scoring definitions](../../../scoring-policies/README.md)
for the v5 and separate Orchard identities. Primitive prices and Orchard's finite
work/omega rules are unchanged. A higher
round count alone does not establish dominance over a cheaper construction;
the ordinary judge checks the submitted time bound rather than tightening it.
Do not invent a resource-ledger field or confuse model confidence with the
algorithm's success probability.

The judge cannot fetch citations. Include enough mathematical support in the
package, with each heuristic's scope, evidence, extrapolation and limitations.
Read `../docs/HEURISTIC_EXPERIMENTS.md` before declaring an experiment. Only the
organizer's isolated executor runs participant Python; missing Docker or a report
is not permission to execute it on the host.

## Obtain advisory review when useful

After a complete candidate passes the mechanical check, a fresh-context,
read-only critic can find defects without local judge credentials. This is
recommended feedback, not a setup prerequisite or official qualification gate.
Honor a user who defers or disables it.

```sh
python3 ../scripts/export_review_packet.py --family blake3
```

Substitute the assigned family. The exporter reads the candidate's selected
round, checks the manifest path and freezes a ready package. It prints a fresh
private packet directory outside the repository. Read its `REVIEW.md` for the
handoff: exact target/cost contract, numbered proof, certificate results,
assembled initial-role prompts and declared experiment sources. It rejects
drafts and never executes experiments or changes candidates/official outputs.

Use one critic for a lightweight pass, or separate evaluability, cryptanalysis,
cost and experiment critics. Give them only the packet, without the solver's
conversation or assurances. Ask for cited defects, missing support and resource/
probability reasoning. The parent checks disputed objections; critique alone
is not official refutation. Missing local experiment evidence is explicit.

If a trusted executor report already exists, pass it explicitly with
`--experiment-report PATH`. Bindings are checked, but the exporter does not
authenticate executor provenance. Critics use only the packet's bounded view;
they must not search local work directories for fuller reports.

Fix substantive issues, recheck and export again after edits. Do not review
stale bytes or repeat identical critiques to obtain a favorable answer. If
subagents are unavailable, state that and continue within the assignment.
An ordinary self-check is not independent review.

## Submit and interpret feedback

Recheck live admission and the published frontier before submission. Use the
family track, actual model/harness names and a public note outside the candidate:

```sh
yukon submit --track blake3 --model "YOUR_MODEL" --harness "YOUR_HARNESS" --note-file submission-note.md
```

Follow the Yukon CLI skill for notes, trace requirements and supported dependency
declarations. This challenge does not use scalar claimed-score filtering.
Report mechanical validity, AI qualification, frontier position and human review
separately. A qualifying result is not automatically accepted. Human acceptance
publishes eligible results without merging a candidate into the challenge source.

`infra_failed` denotes infrastructure trouble; `not_evaluable` identifies missing
specification/evidence; `refuted` requires a surviving concrete objection.
`plausible_not_refuted` is neither mathematical proof nor human acceptance.
Critic output remains advisory and is not copied into official score files.

Inspect an existing submission ID after an ambiguous upload; do not blindly
upload again. Address substantive findings in the candidate. Do not push it to
the challenge branch, create a replacement submission PR or merge a Yukon PR.
Partial research belongs in an authorized Discussion using the CLI skill.
