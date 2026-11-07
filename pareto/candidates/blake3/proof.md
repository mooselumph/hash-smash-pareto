# Sparse-checkpoint salted rho for complete BLAKE3-r3

1. Scope and result. This is a classical ordinary collision construction for
complete unkeyed BLAKE3 with prefix rounds 0,1,2 in every compression. It uses
one explicit fixed-target heuristic H-checkpoint256. Conditional on that premise,
its success probability is at least 0.39. Its deterministic total work is below
2^128.69 selected-target compression units, including failures, and all memory
is at most 2^20 bytes. Consequently its normalized time-memory cost is 128.69.
This is a conditional generic construction, not a full-width executed collision,
unconditional security theorem, new differential, or human-accepted result.
The submitted finite probes have not been executed locally. Their source is
provided for trusted organizer execution; no favorable observation is asserted.

2. Exact complete target. Let F be the selected complete BLAKE3-r3 hash with
standard fixed IV, unkeyed mode, standard schedule and feed-forward. For salt S
and state x, each an unsigned 256-bit word, define M_S(x)=LE32(S)||LE32(x), where
LE32 denotes exactly 32 little-endian bytes. Define f_S(x)=LEinteger(F(M_S(x))).
The message has exactly 64 bytes, so the complete target is one root compression
with CV=IV, counter=0, true block length=64, flags CHUNK_START|CHUNK_END|ROOT=11.
Its output is all eight first 32-bit words, little-endian, not an internal CV.
Every target call uses prefix rounds 0,1,2 and the standard between-round message
permutation. No tree parent or additional root call exists for these one-block
messages. Salt is part of the ordinary message; it changes neither key nor IV.
For fixed S the injection is one-to-one. Equal full f_S values at distinct
predecessors therefore produce two distinct ordinary messages with equal entire
256-bit digests. Both messages satisfy the finite-byte-string domain below
2^64 bits. Near-collisions, changed IVs, truncated target outputs and free starts
are not accepted by the full attack.

3. Coins, parameters and data structures. Draw S,x0 independently uniformly from
all 256-bit words, using two priced random-word draws. Set N=2^256, m=2^128,
D=2^116=m/4096, and B=m+D. Execute one bounded attempt. There are no restarts,
parallel processors, advice or retained external precomputation. Counters and
states fit 256-bit words. Let x_i=f_S^i(x0). Store checkpoints at indices aD.
Use a chronological array C[a]=x_(aD) and a separate sorted array of records
(state,index), with the actual orbit index in the second word. Each state/index
record uses two 32-byte RAM words. Use ordinary deterministic binary search for
exact state equality in the sorted array. Insert new checkpoint records by
shifting subsequent records, preserving order. This costs finite work and is
charged below. No randomized hash table or expected lookup bound is used.
Only checkpoints, not all intermediate orbit states, are retained.

4. Concrete detection and recovery controller. Initially C[0]=x0 and the sorted
array contains (x0,0). Set x=x0. Execute the following finite loops, with bounds
and all failure paths exactly as specified. A lookup returns an exact matching
state's index or NONE; it never tests only a digest projection in the full attack.

    for j = 1,...,B:
        x = f_S(x)
        k = sorted_lookup(x)
        if k is not NONE:
            goto RECOVER
        if j == B: return FAILURE
        if j mod D == 0:
            append x to C
            sorted_insert(x,j)
    return FAILURE
    RECOVER:
        if k == 0: return FAILURE
        q = floor((j-D)/D)*D
        if q < 0: return FAILURE
        left = C[k/D-1]
        right = C[q/D]
        for h = q+1,...,j-D:
            right = f_S(right)
        if left == right: return FAILURE
        for h = 1,...,D:
            a = left; b = right
            left = f_S(left); right = f_S(right)
            if left == right:
                if a == b: return FAILURE
                A=M_S(a); Bmsg=M_S(b)
                recompute full F(A),F(Bmsg)
                if A != Bmsg and F(A)==F(Bmsg): return (A,Bmsg)
                return FAILURE
        return FAILURE

Every loop and recovery is bounded, even outside the sufficient success event.
At any hit k>0, the checkpoint index is a positive multiple of D less than j.
Thus j>D and q is a valid stored index strictly less than j; the guard is extra
safety. At most D-1 right-pointer advances precede the final recovery loop.
The full-output verification is charged even though correctness already implies
it. No null row, pure cycle, cap failure or failed verification is retried.

5. Deterministic correctness and sufficient event. For any fixed S,x0 the orbit
has tail mu>=0 and cycle lambda>=1. The first mu+lambda states are distinct,
and x_(mu+lambda)=x_mu. Consider the event
    E: mu>0, lambda>=D, mu+lambda<=m.
Let k=ceil(mu/D)*D. Then mu<=k<mu+D<=mu+lambda, so this is the earliest
checkpoint inside the cycle, and k>=D. Every earlier checkpoint is on the tail
and can never be revisited. Every later cycle checkpoint has a strictly later
first revisit. Consequently the first exact checkpoint hit occurs at
j=k+lambda <=mu+lambda+D <=m+D=B, at the record with index k. Before that hit
all checkpoints in question have been inserted. No earlier return or spurious
duplicate can preempt the hit, since any equal orbit states are cycle states.

Now left starts at x_(k-D), whose index is strictly below mu. The reconstructed
right pointer equals x_(j-D)=x_(k-D+lambda). Its chronological starting checkpoint
q=floor((j-D)/D)*D was inserted before j; fewer than D advances reconstruct it.
The pointers agree after exactly mu-(k-D) advances, an integer in [1,D]. Prior
to that advance the left pointer is on the nonrepeating tail and the right
pointer is strictly later in the orbit; therefore they cannot already agree.
After the final advance both are x_mu, since they are separated by lambda and
are then on the cycle. Their saved predecessors are distinct and map to the
same full f_S value. Injection of M_S gives a valid ordinary complete collision.
Thus E implies success. Outside E any returned pair still passes full target
verification, so no false collision can be output. Pure cycles hit k=0 first
and are correctly rejected rather than reported as collisions.

6. Explicit score-critical premise H-checkpoint256. For this fixed F and exact
salted 64-byte injection, over independent uniform full-width S,x0, posit
    Pr[mu>0 AND lambda>=2^116 AND mu+lambda<=2^128] >=0.39.
Section 5 then proves algorithmic success at least 0.39. This is a distributional
premise about actual fixed-target walks, not reviewer confidence, not a theorem
from independent coins, and not a claim that reduced BLAKE3 is ideal against
all attacks. A family of permutations, unusually long tails/cycles, or excessive
short cycles could violate it. The resource bound below holds whether it is
true or false. Its added cycle-length condition differs from the preceding
Floyd candidate; prior qualification does not establish this premise.

7. Finite random-mapping supporting calculation. For an independent uniform map
g on N states and uniform start, exposing fresh outputs until the first repeat
gives no-repeat probability product_(i=1)^m(1-i/N). Thus
    Pr[mu+lambda<=m] >=1-exp(-m*(m+1)/(2*N)).
The probability that the first repeat hits x0 within m transitions is at most
m/N. To bound short cycles, at any first-repeat transition i<=m the earlier
states whose indices yield lambda<D number at most D-1. Each fresh output is
uniform, so a union bound gives probability at most m*(D-1)/N for such a repeat.
Subtracting both excluded events (overlap only weakens this lower bound),
    Pr[E] >=1-exp(-m*(m+1)/(2*N))-m/N-m*(D-1)/N
           =1-exp(-m*(m+1)/(2*N))-m*D/N
           >1-exp(-1/2)-1/4096 >0.39322 >0.39.
This is a finite inequality, not an asymptotic approximation. In a random oracle
on 64-byte messages, distinct salts select disjoint input domains and each map
has this law. Transferring enough of that orbit behavior to this fixed reduced
hash is precisely H-checkpoint256. The calculation supplies analytic motivation
and a small margin, not measured full-width evidence or a proof about F.

8. Declared finite probes. Four probes use widths 12 and 16 bits. The two inherited dense
probes retain the following scaled parameters. For a
probe width n, set m_n=2^(n/2), D_n=max(1,m_n/4096), B_n=m_n+D_n. These widths
have D_n=1: every projected state is a checkpoint. Apply the same checkpoint
lookup and recovery controller to low_n(F(S||LE32(x))). The probe keeps both
chronological checkpoints and sorted records, and uses exact comparison on the
projected states. It emits distinct predecessor messages or two nulls for each
supplied trial. Organizer hashing independently checks the low-bit XOR-zero
predicate. These are mask collisions, never full 256-bit witnesses. Both the
root implementation and its true complete-message flags match section 2; only
its low word is needed for these projected walks. Memoization is experiment-only
and never a basis for the attack's time or memory bound.

Salt is the supplied 32-byte organizer seed; the projected start is low_n of
SHA-256(b'rho-start'||seed). This deterministic seed expansion supplies repeatable
probes, not independently ideal full-width coins. There is no seed search,
resampling, hidden discarded failure or optional stopping. No observed count is
asserted before trusted execution. The inherited projection widths are retained
before receiving results for the new controller. For these inherited dense probes, D=1
means the probe does not exercise sparse gaps or extrapolate a confidence bound
for the full-width tail or cycle-length condition. Correctness for arbitrary D
is argued in section 5. The full report, whether favorable or unfavorable, is
needed before exploratory qualification; no local host execution is authorized.

Two additional probes, rho12sparse and rho16sparse, use the same widths but
D_n=m_n/16, namely 4 and 16. They exercise nontrivial gaps and local recovery
using the same controller, sorted arrays and output predicates. Their spacing
ratio differs from full-width 1/4096 and their success frequency is not a
full-width probability estimate. They are declared before any result is seen;
all supplied trials and failures remain included. These probes can expose
sparse-recovery implementation defects that the D=1 probes would miss, without
closing the full-width extrapolation gap. No result is asserted for them.

9. Limits of evidence. Successful 12/16-bit probes can demonstrate finite exact-
target mask events and catch some controller/root defects. They cannot establish
H-checkpoint256, ideal randomness, iid trials or full-width success probability.
Even the additional sparse probes do not test the extremely large spacing
D=2^116. The gap between
those projections and 256-bit walks is enormous, and the random-map margin above
0.39 is small. The heuristic is motivated by the explicit random-map analysis
and the conventional collision-search orbit model, together with whatever finite
evidence the organizer actually produces. No full-width theorem, measured work
at scale, mathematical proof of the heuristic, or rigorous qualification follows
from this package. Unfavorable or inconclusive finite reports must remain visible.

10. Deterministic total-work ledger. The selected cost contract has C=638 word
operations per target compression. Detection uses at most m+D full target calls;
right reconstruction fewer than D; synchronous recovery at most 2D; and final
verification at most two. Thus H<=m+4D+2 for all coins and every failure path.
The chronological array and sorted records hold at most 4097 checkpoints: index
0 and positive multiples of D through m. At the terminal j=m+D no insertion
occurs. Searching at most 4097 records takes at most 14 binary-search iterations.
An iteration can be lowered in at most 16 priced word operations: midpoint
addition/shift, two-word record address arithmetic, key load, equality/order
comparisons and branches, bound update and loop routing. This gives at most
224 operations per detected state. Allow a further 128 per step for input/output
stores, target adapter, current-state/counter update, checkpoint/cap tests and
lookup setup/finalization; this totals 352, below the adopted 384 per target
call. The target compression itself is charged separately by H. Index division
by D and remainder are fixed shifts/masks, not unit-cost general division.
Recovery has no binary lookup and fits the same 384 per-call allowance, including
saved predecessors and loop control. Up to 4097 insertions each shift at most
4097 two-word records. Allow 32 operations per shifted record, plus 512 per
insertion for copying to chronological storage and inserting the new record.
This is below 2^30 word operations. Initialization, two true random words,
constant creation, final output/verification adapters and all finite preliminary
research are covered by a larger fixed allowance of 2^40 word operations. This
also covers zero-loop recovery setup when no target call occurs there. Thus
    W <=384*(m+4D+2)+2^40,
    T = H+W/638
      <=(1+384/638)*(m+4D+2)+2^40/638
      <1.604*2^128+2^32 <2^128.69.
The actual leading coefficient is below 1.604; 2^0.69 exceeds 1.613. No omitted
restart, success amplification, randomness source, table sort, lookup or recovery
cost is needed. The fixed 2^40/638 charge is below 2^31, as declared in
preprocessing_log2. Work is total across the single processor, not latency.
The ledger prices a word-RAM algorithm with a selected compression primitive,
not the source-level Python runtime used solely for finite experiment evidence.

11. Memory ledger. Reserve 4097 chronological words =131104 bytes and 4097
sorted two-word records =262208 bytes. Their total is 393312 bytes. Reserve
65536 bytes (2048 fixed 32-byte instruction/literal slots) for the uniform
controller, binary lookup, insertion, adapters and constants. Straight-line
blocks and loops, not unrolled orbit iterations, implement this program. The
controller has under 40 live words; reserve another 8192 bytes for registers,
compression workspace, input/output buffers and stack. Total is 467040 bytes,
strictly below 2^20=1048576, leaving over half the allowance as implementation
slack. An insertion needs only a two-word temporary, not a second table. There
is no recursion, history array, extra runtime, advice or nonuniform code.
Representing the 32-bit compression words as full RAM words still fits the
workspace reserve. At most four output words represent the returned two 64-byte
messages. The claim reports conservative raw memory_log2_bytes=20. The formula
is 128.69+max(0,20-20)=128.69; memory below one MiB adds no cost penalty.

12. Provenance and revision. This work directly retains from
6f55e9bf-8eb5-49e5-b37c-0d379ddbe883 the complete 64-byte root specialization,
salted state injection, fixed-target heuristic framing, random-mapping argument,
finite root-probe implementation and compression-based resource accounting.
It retains the cap m=2^128 explored in submission
1062e941-1aa2-42fd-ad11-f75feea550fc, whose score is not presumed here.
The sparse-checkpoint detection and bounded local recovery replace Floyd's
three-evaluation detection and full-tail recovery. This is generic orbit search,
not a new BLAKE3 differential. Earlier methods supply context and attribution;
this package supplies all mathematics needed without fetching outside papers.
The new cycle-length restriction, sparse table memory and binary-search costs
are explicit. The lower cost is conditional on H-checkpoint256 and is not an
unconditional improvement of earlier nonheuristic collision bounds. Official
execution, AI review, human publication and promotion are distinct outcomes.

13. Revised finite controller charge. This revision directly builds on public
submission 2aa896d8-f152-42a9-861d-9dc5ba03748b. It preserves its exact
controller, parameters, experiment bytes, sufficient event and probability
premise. The earlier 512-operation per-call ceiling is replaced by 384.
The detection charge already derives 224 search operations plus 128 other
operations, totaling 352; the new ceiling retains 32 operations of slack.
For recovery no search occurs. A synchronous pair iteration charges its two
compression primitives separately and has at most 128 non-compression
operations total: pointer saves (4), two message adapters and digest assembly
(64), state equality and predecessor tests (8), loop increment/test/routing
(12), and 40 spare for addresses, loads, stores and branches. Reconstruction
uses at most 128 auxiliary operations per call for the same adapters and
loop control. Exceptional entry/exit and verification use the fixed allowance.
Checkpoint insertions retain the separate 2^30 charge, covered by 2^40,
and are never hidden in the per-step ceiling. No target internals are
discounted and no expected operation counts replace deterministic bounds.
Thus the revised total leading coefficient is exactly bounded by
(1+384/638)*(1+4/4096)=1.603445214537618, strictly below 2^0.69.
The unchanged negligible fixed allowance fits the remaining positive slack.
This is an accounting refinement of a conditional generic construction.
It neither supplies new evidence for H-checkpoint256 nor establishes
full-width success unconditionally.
