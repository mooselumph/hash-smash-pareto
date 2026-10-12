# Orchard accounting: disclosure to the judges

Resource policy: `orchard-field-ram-v2`, with algebraic rules `orchard-finite-work-v1`.
New successor score projection: `hashsmash-orchard-tm-v1`, canonical SHA-256
`497b0e3c33b57ab31fa79c957c22290327c50238793754184d48c93a86e363d7`.
Organizer decision date: 11 October 2026.

This note records the rules selected after the Poseidon proposal and organizer
review. It explains the additional decisions delegated to the implementer so
that judges can assess their consequences. The authoritative runtime contract is
[orchard-cost-v2.json](./orchard-cost-v2.json), included in the evidence supplied
to every review and bound into the target configuration hash. The separate
[normalized scoring definition](./scoring-policies/hashsmash-orchard-tm-v1.json)
is also bound into new evidence. It retains all resource prices and finite-work
rules below, then projects raw time and memory at the trusted Pareto boundary.
The [scoring contract](../scoring-policies/README.md) explains source attribution,
metadata and fresh-registration requirements.

## Decisions

| Item | Selected rule |
| --- | --- |
| Instance | Orchard/Pallas P128Pow5T3, its deployed constants and MDS, eight full rounds |
| Reduced instances | Full rounds 0–3, first r partial rounds beginning at 4, full rounds 60–63 |
| Initial accepted counts | r = 1 and 2 partial rounds, each with eight full rounds; live admission is authoritative |
| Primitive prices | Field add/subtract/multiply and primitive 256-bit word operations each have base weight 1 |
| Normalization | Divide complete charged work by `C(r) = 216 + 21*r` |
| Matrix exponent | ω = 2.8 for applicable algebraic estimates parameterized by ω |
| Hidden coefficient | No universal default; require an explicit coefficient or finite upper bound supported by the algorithm or analysis |
| Logs | Base 2 for newly stated expressions; retain all log factors and convert other specified bases exactly |
| Setup and lower-order terms | Include them, or cover them with a justified finite upper bound |
| Probability | A finite budget achieving the claimed success probability, at least 0.39 |
| Memory | Count and review bytes; the cost axis adds max(0, memoryLog2Bytes - 20), with a one-MiB floor |
| Objectives | Maximize partial rounds; minimize normalizedTimeMemoryLog2 |
| Baseline | No required qualified attack baseline; bundled drafts remain invalid smoke checks |

The review supplied by the organizers selected ω = 2.8 and endorsed the current
target and weighted accounting choices. The implementer's additional choices are
the finite-coefficient rule, explicit log treatment, dimension/rounding rules and
the evidence requirements below. These are policy conventions, not claims about
optimal algorithms or physical runtimes.

## Turning an algebraic estimate into a score

A solver must identify the algorithm and instantiate its finite dimensions:
selected rounds, actual Pallas field, polynomial degrees, matrix shapes,
sparsity, block counts, padding and repetitions. An exponent alone is not a
work count.

1. Use ω = 2.8 where a supported algebraic bound contains the parameter ω.
   Preserve its other factors and applicability conditions. This does not supply
   a free matrix operation, prove a finite `n^2.8` implementation, or let a solver
   discount the counted work of an explicitly cubic algorithm. A concrete
   recurrence or operation count is charged as stated. A specialized sparse or
   structured algorithm needs its own supported finite analysis.
2. Give an explicit positive coefficient or conservative finite upper bound.
   Derive it from the specified algorithm, recurrence, or a reproduced finite
   result. Do not turn `O(n^ω)`, `Theta(n^ω)` or soft-O into exactly `n^2.8`.
   There is no default coefficient of 1, 2, 10 or 100: none would bound an
   unspecified hidden constant. Algorithm-specific coefficients are submission
   evidence, not another organizer parameter left for judges to invent.
3. Retain logarithmic factors. For example, `ln(n)` equals
   `ln(2) * log2(n)`; changing the base without adjusting the coefficient changes
   the cost. Expand soft-O before giving a numerical score. The power of a log
   comes from the chosen algorithm or bound; no universal log exponent is imposed.
4. Include finite setup, input/output, additions, memory access, preprocessing,
   failure and amplification work. Lower-order terms can be folded into a looser
   supported bound valid at the actual dimensions, but cannot disappear merely
   because the leading term eventually dominates. Round integer dimensions,
   recursion depths and repetitions up where the algorithm requires it. For
   rectangular multiplication, justify the rectangular/block calculation or
   explicitly charge square padding at the padded size.
5. Supply a finite work budget with a success argument. An expected running time
   or one successful experiment alone does not establish the cost of attaining
   probability 0.39. Account for the tail, restarts and amplification actually
   used. Charge total work over all processors, not elapsed parallel time.
6. Sum all nonoverlapping work before taking log2. Use enough precision, or
   log-space arithmetic, to retain relevant small terms beside enormous ones.
   Do not round a submitted upper bound downward. Display rounding is separate.

If a paper counts only field multiplications, the solver must add or bound its
other charged work. Inversion and exponentiation still expand into constituent
operations. Conversely, do not double-count a permutation's reference arithmetic
when a one-unit call already pays for it. Additional input generation, packing,
lookup and collision verification remain charged as applicable.

For H reference permutation calls and W other primitive operations, when those
terms cover the complete budget, the normalized cost is `T = H + W/C(r)` and the
raw time bound is `timeLog2 = log2(T)`. The new Pareto cost axis is
`timeLog2 + max(0, memoryLog2Bytes - 20)`, equivalently
`log2(T * max(1, memoryBytes / 1048576))`. Memory is not an extra objective or a
tie-break. A fully expanded operation count is instead divided once by C.
At r = 1, C = 237 (156 multiplications plus 81 additions); at r = 2, C = 258
(168 multiplications plus 90 additions). The denominator remains the fixed dense
reference implementation even if an attack uses an optimized implementation.

## Example and sensitivity

Suppose an analysis supports a **complete** primitive-work budget

```
W(n) = 5*n^2.8*log2(n) + 12*n^2 + 1000
```

and independently supplies the required success argument. At n = 1024 this is
13,434,356,712 primitive operations. For r = 1, the normalized time is about
56,685,049.42, whose log2 is 25.75646494. A ceiling of 25.76 covers this illustrative
arithmetic; submitting 25.75 would not. For r = 2, the same work has log2 25.63398094
because its reference permutation is more expensive. Actual attacks must of
course recompute their own work when the round count changes. These numbers are
raw time bounds. If the example used 2^30 bytes of reviewed memory, the submitted
r=1 time bound 25.76 would project to normalized cost 35.76. At one MiB or less
it would remain 25.76. The raw time and memory metrics remain separately visible.

This is an accounting example, not an attack, baseline or endorsed coefficient.
Dropping the coefficient 5 would underprice its leading term by a factor of 5;
dropping the log at this dimension would underprice it by a further factor of 10.
Multiplying an entire budget by a factor k adds `log2(k)` to the score. This is why
prefactors matter even on an exponent leaderboard.

## Evidence and judge handling

Include the formula, coefficient justification, assumptions and applicable regime
inside the candidate. A citation or link alone is insufficient because the judge
does not fetch external sources. Reproduce the necessary argument or calculation.
Small-instance measurements may support an explicitly declared extrapolation;
they do not silently become a bound at cryptanalytic dimensions. State the tested
regime, extrapolation, limitations and score sensitivity for such heuristics.

The original exploratory qualification policy, `paired-lanes-v1`, still applies.
This update adds no automatic numerical confidence score, operation-ledger schema,
or hard rejection gate. Evidence-supported heuristic estimates remain reviewable.
An unsupported coefficient or bare asymptotic expression leaves the cost
obligation unresolved; it must not receive an unconditional supported label.
A definite understated bound is handled by the existing adversarial challenge
process. The judge must not invent a coefficient, repair the candidate, or publish
an improved replacement number. AI qualification remains separate from human
acceptance.

## Tradeoffs and scope

These rules favor comparable total-work estimates over accepting published
headline exponents unchanged. Some papers will require substantial expansion
before they support a numerical submission. We accept that cost instead of
introducing an arbitrary global safety multiplier or silently free operations.

The model remains abstract. Equal field-addition, field-multiplication and word
weights are not hardware calibration. ω = 2.8 is a selected convention, not a
claim about the best achievable exponent. Explicitly counted algorithms and
convention-based algebraic estimates must be identified as such in the evidence.
Memory above one MiB now increases the normalized cost, while raw storage remains
visible in the reviewed memory metric. This is still an abstract accounting choice,
not a measurement of physical runtime or a cross-family security comparison.

The SHA-256, SHA3-256 and BLAKE3 cost models and shared judge prompts are unchanged.
V1's Orchard prices and normalization are retained; v2 versions the added estimate
rules. Historical evidence remains tied to its original source and evaluation.
Changing accepted round counts is a live admission update; changing these rules
requires an evaluation refresh when the objective contract is unchanged. Changing
from the old time-only objective to this normalized objective instead requires a
fresh registration; a Yukon reorg cannot rename immutable objectives. Old dev
source/evidence remains pinned to `8c81a39eb987a3235fa38569435474671fed5b1b`.
The one stable Orchard lane supports r = 0–56,
but this decision initially admits only r = 1 and 2. Neither choice asserts a
first-unbroken security boundary.

## Sources

- [Poseidon proposal, discussion 380](https://github.com/Layr-Labs/hash-smash/discussions/380),
  especially §5 and Appendix E: organizers select algebraic pricing, treatment of
  hidden factors and ω. This note records the selected rules rather than claiming
  that the proposal specified them.
- [Runtime cost contract](./orchard-cost-v2.json) and
  [trusted target adapter](./targets.py).
- [Existing cost-review rubric](../judge/prompts/lane-cost-v1.md) and
  [qualification policy](../judge/policies/paired-lanes-v1.md).
