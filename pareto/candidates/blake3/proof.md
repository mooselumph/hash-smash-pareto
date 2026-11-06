# Bounded salted rho for complete BLAKE3-r3

1. Status and scope. This is a generic, constant-memory classical collision
construction with one explicit score-critical heuristic about the fixed reduced
BLAKE3 target. It is not an unconditional collision bound, executed full-scale
attack, collision certificate or new differential. The bound is raw total work
at most 2^131 target compressions, at most 2^14 bytes of memory, and success
probability at least 0.39 conditional on the disclosed heuristic H-rho256.
The normalized cost is 131 because memory is below one MiB. A package containing
submitted finite-projection probes permits the organizer to generate empirical
evidence before review. No local execution result or favorable frequency is
asserted. The original unconditional batch package remains a separate submitted
result; this candidate replaces its probability argument rather than improving
that argument unconditionally.

2. Complete target and injection. Let F be the selected complete unkeyed
BLAKE3-r3 hash, with its fixed standard IV and all 256 output bits. For each
256-bit salt S and 256-bit state x, define
    M_S(x) = LE32(S) || LE32(x),
    f_S(x) = integer represented by F(M_S(x)) in little-endian order.
LE32 means exactly 32 bytes, not 32 bits. M_S is an injection for fixed S.
Each message has exactly 64 bytes, so the complete hash is a single final root
compression: input CV standard IV, true length64, counter0, flags
CHUNK_START|CHUNK_END|ROOT=11. It uses prefix rounds0,1,2, their usual eight G
calls and standard between-round message permutations, and standard feed-forward.
Return the first eight 32-bit output words little-endian. There is no chunk-CV
substitution, missing parent or second root hash. The domain has complete
512-bit messages, safely below the 2^64-bit input-length limit. Both compared
outputs are full 256-bit digests. Salt is part of the message, not a secret key,
changed IV, free-start state or alteration of the standard mode.

3. Coins and finite stopping rule. Draw S and x0 independently and uniformly
from the full 256-bit word domain: exactly two fresh random word operations.
Let N=2^256, L=2^128 and m=3*2^127=(3/2)L. Store these constants explicitly.
Run exactly one bounded attempt. There is no uncharged random-map oracle,
restart, parallel processor, advice, precomputed table or seed expander in the
claimed attack. All walking states are actual deterministic f_S iterates.
The finite probes below use deterministic seed expansion only as reproducible
evidence; that is distinct from these independent ideal algorithmic coins.

4. Concrete algorithm. Every counter fits in one 256-bit RAM word. A function
call below computes f_S by evaluating the stipulated complete target on its
actual 64-byte message. Keep no history of the walk. Use this controller:

    slow = x0; fast = x0; met = false
    for i = 1,...,m:
        slow = f_S(slow)
        fast = f_S(fast)
        fast = f_S(fast)
        if slow == fast: met = true; break
    if not met: return FAILURE
    left = x0; right = slow
    if left == right: return FAILURE
    for j = 1,...,m:
        a = left; b = right
        left = f_S(left)
        right = f_S(right)
        if left == right:
            if a == b: return FAILURE
            A = M_S(a); B = M_S(b)
            recompute both complete F(A), F(B)
            if A != B and F(A) == F(B): return (A,B)
            return FAILURE
    return FAILURE

The extra verification is deliberately charged, even though the construction
already computes the equal outputs. Equality never accepts only a projection.
No later candidate or independent attempt is tried after any failure.

5. Deterministic correctness. For a fixed S,x0 write x_i=f_S^i(x0). Since
f_S maps N states into themselves, its orbit has tail length mu>=0 and cycle
length lambda>=1: x0,...,x_(mu+lambda-1) are distinct and
x_(mu+lambda)=x_mu. If mu>0, the two distinct predecessors x_(mu-1) and
x_(mu+lambda-1) map to the same state. By injection of M_S they yield different
complete messages, with equal full F outputs, not just equal chaining values.

At detection step t, slow=x_t and fast=x_(2t). They meet for any t>=mu
that is a positive multiple of lambda. For mu>0, the smallest such t is
lambda*ceil(mu/lambda), which is less than mu+lambda and positive. Hence
mu+lambda<=m and mu>0 ensure detection before the cap. At detection, t is a
multiple of lambda. Resetting the left pointer to x0 and retaining right=x_t
makes the two pointers meet after exactly mu recovery advances: before mu,
one pointer is on the distinct tail and the other is strictly later on the
orbit; at mu they coincide because t is a multiple of lambda. At the last
advance their saved predecessors a,b are distinct and have equal images.
Since mu<m, the recovery cap suffices. Pure cycles mu=0 are expressly rejected
by the initial recovery equality test. They do not produce false positives.
Even outside this sufficient event, any returned pair passes exact validation.

6. Explicit score-critical premise H-rho256. For the fixed selected F, over
independent uniform S,x0, posit
    Pr[mu(f_S,x0)>0 AND mu(f_S,x0)+lambda(f_S,x0)<=m] >= 0.39.
This is a concrete, falsifiable distributional premise about this salt family
and full-output walks at cap m, not the probability that a reviewer believes
an argument. Conditional on this premise, section5 proves attack success at
least0.39. Independence of the two input words does not by itself imply this
premise. It is not an assertion that the reduced hash is secure or that three
rounds have ideal behavior against differential cryptanalysis. The premise
concerns generic orbit lengths, tails and cycles for one precisely defined
message injection. A permutation-like salt family, extremely long walks, or
concentration on pure cycles could make it false. More output collisions in
another domain do not by themselves imply it. It is deliberately separate
from the resource bound, which holds regardless of whether the premise is true.

7. Oracle calculation, not a theorem about fixed BLAKE3. For an independently
uniform random mapping g on N states and uniform x0, the probability that the
first m transitions contain no repeated state is
    product_(j=1)^m (1-j/N).
The sum of j/N and 1-z<=exp(-z) give
    Pr[mu+lambda<=m] >= 1-exp(-m*(m+1)/(2*N)).
The probability of returning to the initial state within m transitions before
any other repeat is at most m/N: condition on no earlier repeat, and the next
fresh random output hits x0 with probability1/N. A union bound suffices.
Consequently
    Pr[mu>0 AND mu+lambda<=m]
       >= 1-exp(-m*(m+1)/(2*N))-m/N
       > 1-exp(-9/8)-(3/2)*2^-128 > 0.675 > 0.39.
No limit approximation is needed. In a full random oracle on 64-byte inputs,
distinct salts select disjoint message sets, each inducing such a random map.
This establishes a substantial margin in that model. Transferring enough of
this behavior to the fixed three-round target is exactly H-rho256, not a hidden
step of the proof. The random-map calculation is analytic supporting evidence
for the shape and margin of the premise, not empirical confirmation of it.

8. Declared finite experiments. The manifest has two python-message-pairs-v1
probes, rho12 and rho16. They apply the same bounded Floyd and predecessor
controller to the actual selected complete target, with state spaces n=12
and n=16. For each state integer z in [0,2^n), the corresponding message is
S||LE32(z), of full length64. The step is low_n(F(S||LE32(z))), and the cap
is 3*2^(n/2-1). Thus these are projections of full exact-target hashes, not
a separate toy compression or a changed round count. All failed trials return
two null messages; no supplied trial is discarded or resampled.

For each organizer seed, S is the 32-byte seed and x0 is low_n of
SHA-256(b'rho-start'||seed). This is deterministic reproducibility machinery,
not independently certified randomness or the full attack's coin generation.
The program uses a per-trial memoization cache only to reduce finite-probe
execution time; caching does not change the orbit or stopping rule, and no
attack time or memory claim is inferred from it. The source implements the
64-byte three-round root directly. Only its low output word is needed by
these small projections. The trusted organizer independently checks both
returned complete messages under the selected full hash and the declared
12-bit or16-bit output-XOR-zero mask. These are mask events, emphatically not
complete 256-bit collision witnesses. Source arithmetic and all null rows are
visible for review. No participant claimed timing, total, runtime, internal
operation count or independent-trial interval is offered as trusted evidence.

The two widths and cap were selected before obtaining any result. There is no
local participant execution, seed search, selected favorable result or optional
stopping. The declared organizer execution must complete before qualification.
The experiment report, whether favorable or unfavorable, is part of evaluation.
Expected random-map success is of order0.65 at these caps after the finite
pure-cycle correction; no observed count is asserted here. Full reports, not
this expectation, determine what finite evidence actually exists.

9. Extrapolation limits. Finite projected successes can establish that this
specific controller finds mask collisions on actual-target salted walks at
those widths. They can reveal a gross controller error or pathologically short
or long projected behavior. They cannot prove independent oracle outputs,
validate H-rho256 at the full width, rule out large-state structural effects,
or furnish a confidence lower bound for full-target success. Salt/start seed
expansion and repeated orbit values do not establish iid Bernoulli trials.
The test conditions do not match full independent coins exactly. Moving from
12/16 bits to256 bits spans an enormous untested regime. The argument supporting
H-rho256 consists of the explicit random-map analysis, the conventional generic
rho construction, and whatever exact-target finite-projection evidence the
organizer actually produces. It remains a heuristic even if all probes pass.
No rigorous qualification, promotion or human acceptance is asserted.

10. Deterministic complete cost. The selected-round normalization is C=638
primitive word operations per target compression. For all random coins, the
Floyd phase performs at most3m complete target evaluations; the recovery phase
at most2m; verification at most2. Hence H<=5m+2, counting every root call.
No parent/chunk work is omitted for the exact single-block input family.
There is one processor, so this is total work, not parallel wall-clock time.

A conservative auxiliary ledger is W<=128m+2^20 word operations. At most16
auxiliary operations per evaluated target cover actual salt/state input stores,
metadata setup, output placement, pointer/address arithmetic and call/return
control, beyond the separately priced compression. Thus the at-most5m calls
in the two loops consume at most80m auxiliary operations. Each Floyd iteration
uses at most24 additional operations for state assignment/control, equality
comparison and branch, increment, cap comparison/branch and controller routing.
Each recovery iteration uses at most24 for saving a,b, updating its two pointers,
equality/cap tests, increment and exit routing. The two loops together consume
at most48m, giving128m. These are literal finite upper allowances for constant
sequences of word instructions; no multiplication, library search, table lookup,
long message copying or variable-length encoding is hidden in a single step.
Two random word draws, counters and literal initialization, final distinctness
check, two verification adapters, serialization of two64-byte messages and
failure/output control are covered by the fixed2^20 allowance. Experimental
research is not a precomputed attack table; even a finite preliminary execution
budget below2^40 operations, if charged, is negligible and can replace the fixed
allowance by2^40 without changing the displayed bound. Use that larger fixed
allowance for the final conservative claim.

Therefore for every execution, with or without success,
    T <= (5m+2)+(128m+2^40)/638
      = (5+128/638)*(3/2)*2^128 +2+2^40/638
      < 7.801*2^128+2^32 < 8*2^128 = 2^131.
Randomness, failures, detection, recovery, output and all preprocessing are
included. preprocessing_log2=31 bounds2^40/638<2^31 compression equivalents.
There is no restart or success amplification to pay for: H-rho256 concerns this
one finite attempt. The probability argument uses fresh independent input words;
no pseudorandom generator is silently substituted in the claimed algorithm.

11. Memory and uniform implementation. Code, constants, all retained randomness,
working state, target workspace and output fit2^14 bytes. Reserve384 fixed32-byte
instruction slots=12288 bytes for the entire uniform controller and target-call
adapter. A direct lowering of the section4 controller uses at most192 slots:
16 for random draws/initialization,32 for input/metadata/target-call adapter,
24 for Floyd loop and cap,32 for predecessor recovery and cap,32 for verification
and output,16 for literals/counter setup,16 for fixed-width byte encoding,
8 for failure/termination and16 for remaining literal initialization. Their sum
is192; a second192 slots is deliberately reserved for call linkage, control
lowering and implementation slack. This is a word-RAM program with a selected
compression instruction as a priced primitive, not an uncounted Python runtime.
Constants/literals occupy at most16 words=512 bytes. Reserve64 words=2048 bytes
for all registers, input/output state, counters, salt/start, saved predecessors,
flags, adapter temporaries and target working state. The controller alone needs
fewer than24 live words: its states and salt/start use at most8, counters and cap
3, previous pointers2, flags and addresses at most8; the remaining space covers
compression v/message/IV working words. Even representing each of the sixteen
32-bit v words and sixteen message words as a full256-bit RAM word uses only32
additional words. Returned messages/digest and alignment occupy a further256
bytes. Total is12288+512+2048+256=15104<16384. No recursion, array of iterates,
nonuniform code, field table, advice or growing stack is used. Experimental
Python memoization belongs only to organizer evidence generation and is not
part of this claimed controller. Raw memory log2 bytes14 is an upper bound;
normalized cost is131+max(0,14-20)=131.

12. Sources and distinction from the prior candidate. The generic rho/Floyd
method and its application to hash collisions are established prior work;
see van Oorschot and Wiener, Parallel Collision Search with Cryptanalytic
Applications, section2, https://people.scs.carleton.ca/~paulv/papers/JoC97.pdf .
The paper motivates the method, not the fixed-target premise. Everything needed
for this finite controller and conditional bound is supplied above. No novelty
in the generic rho method or its birthday scale is claimed. The present package
specializes the standard method to the exact salted64-byte complete BLAKE3-r3
family, fixes finite caps and costs, and declares two bounded projection probes
and the exact extrapolation gap. The target compression implementation in the
probe follows organizer verifier/blake3.py and the standard BLAKE3 schedule.

The preceding submission0c3bb03b-7cea-417b-bb13-4ba312f5686b supplied the same
64-byte single-root specialization and compression-priced accounting context;
this package retains that limited material and declares it as a dependency.
Its four-wise field generation, sorting networks, fixed-target second moment,
batch memory layout and unconditional probability proof are not used here.
Earlier raw exponent242.19 is a comparison only. This new131 claim is conditional
on H-rho256; the comparison is not an unconditional improvement of that theorem.
The target root specialization was itself retained there from
6ab87697-8123-466e-b3c4-d4d59b1868c4, disclosed as upstream provenance.
