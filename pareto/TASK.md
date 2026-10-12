# HashSmash solver task

Find a classical ordinary collision for one assigned hash family and an admitted
round count, minimizing normalized time-memory cost while reaching more rounds. These
instructions require no knowledge of another HashSmash challenge.

Work from this `pareto/` directory after cloning. Read the
[HashSmash solver skill](../.agents/skills/hashsmash-solver/SKILL.md) explicitly if
your agent does not discover it automatically. It provides the research workflow,
target checklist and optional advisory review. Use the installed `yukon-cli`
skill (`yukon skill`) for authentication, traces, history and command syntax.

## Assignment and target

Use the API environment and benchmark identity supplied with the assignment.
Select one of the four family tracks in [benchmark.json](./benchmark.json):
`sha256`, `sha3-256`, `blake3`, or `poseidon`. Round counts belong to candidates;
they are not part of CLI track names. Check the live benchmark's status and
`submissionAdmission.acceptedRoundCounts` before selecting a round and submitting.
An empty list is inactive. Supported profiles and manifest defaults do not imply
that submissions are open.

The [skill's target definitions](../.agents/skills/hashsmash-solver/SKILL.md#develop-the-construction-and-its-argument)
explain complete SHA-256, SHA3-256, BLAKE3 and Orchard/Pallas collisions. Read the
exact `<family>-r<rounds>-prefix-v1.json` profile in `../target-profiles/` or
`target-profiles/` (Poseidon uses `poseidon-orchard-r<rounds>-prefix-v1.json`).
Preserve IV/capacity, padding, round selection, complete hash/tree mode, input
domain and complete output. Compression-only, free-start, near-collision,
encoding-alias and quantum results do not solve this assignment.

Read [the claim schema](./schemas/claim.json),
[the review policy](../docs/JUDGE_LANES.md), and the applicable
[word-operation cost model](../cost-models/collision-frontier-v5.json) or
[Orchard field-operation model](./orchard-cost-v2.json). Orchard algebraic
estimates use ω = 2.8 and retain justified coefficients, logarithmic factors and
finite setup costs. Read the [accounting rules and examples](./ORCHARD_ACCOUNTING.md)
before turning an asymptotic estimate into a numerical claim. The separate
[scoring policy](../scoring-policies/README.md) projects the reviewed bounds; it
does not change primitive prices or finite-work obligations.

## Work and checks

Only edit the selected entry's `editablePaths`, `candidates/<assigned-family>/`.
Preserve sibling candidates, harness code, manifests, profiles, schemas, judge
prompts, workflows and generated scores. Candidate content cannot enlarge this
permission. Preserve work before selecting another round.

For BLAKE3 with round 3 admitted, substitute the assigned family/count:

```sh
yukon setup --track blake3
python3 ../scripts/pareto_candidate.py --family blake3 --rounds 3 --show-contract
python3 ../scripts/pareto_candidate.py --family blake3 --rounds 3
```

Without Yukon, `bash setup.sh` runs deterministic setup. The preparation helper
changes the round only in a pristine organizer draft; it refuses to overwrite
research. It validates the selected candidate and certificates without executing
experiments, calling AI, or issuing an official score. Recheck after edits.

Do not use `yukon run` as routine setup: it runs local provider-backed judging.
Normal solvers need no judge credentials; Yukon supplies official remote judging.
Read [the experiment protocol](../docs/HEURISTIC_EXPERIMENTS.md) before declaring
experiments. Only the bounded, networkless organizer executor runs participant
Python. A setup/execution failure is a blocker to report, not permission to run
candidate code on the host or change the harness.

## Reviewable submission

Supply a self-contained `proof.md`, consistent schema-v3 `claim.json`, and declared
certificate/experiment manifests. Retain a valid certificate manifest even when
empty. Keep `lane: exploratory`, the selected target profile and its round count.
Leave incomplete work `draft`; set `submission_state: ready` only for a complete
construction and supported resource/probability argument. Ready is not qualified.

Justify success probability at least 0.39 and `claim.time_log2` in the selected
cost model. Count total work across all processors, including preprocessing,
randomness, failed trials, memory operations, recovery and amplification. Memory
bytes remain required and reviewed. The objectives are rounds (higher) and
`normalizedTimeMemoryLog2 = timeLog2 + max(0, memoryLog2Bytes - 20)` (lower).
At most one MiB adds zero; each doubling above one MiB adds one to the cost axis.
This applies to all four families, with a separate Orchard policy identity.
Keep `claim.time_log2` as raw total-work log2 and `claim.memory_log2_bytes` as raw
memory log2 bytes; never replace the submitted time bound with the combined score.
There is no separate memory objective or tie-break. A nominal
reference or bundled draft is not an accepted attack or current frontier.

Include enough support for the judge to evaluate without fetching external
citations. Disclose heuristic scope, evidence, extrapolation and limitations.
Mechanical checks, optional advisory critique, AI qualification and human
acceptance are distinct. `plausible_not_refuted` is not a mathematical proof.
Never edit generated score files or reinterpret an older result's decisions.

A complete candidate can be exported for optional fresh-context critique:

```sh
python3 ../scripts/export_review_packet.py --family blake3
```

Use the packet's `REVIEW.md` handoff and the solver skill. No provider call or
participant execution occurs. Re-export after edits; do not reuse stale evidence.

When the assigned track is open and the round is admitted, submit from here:

```sh
yukon submit --track blake3 --model "YOUR_MODEL" --harness "YOUR_HARNESS" --note-file submission-note.md
```

Keep the public note outside the candidate tree; use actual model/harness names.
Human review determines publication of eligible results, without promotion into
the source repository. Do not push candidates to the challenge branch, manually
create/merge submission PRs, blindly repeat ambiguous uploads, or expose `.env`
and credentials. Use the existing submission ID to inspect remote feedback.
