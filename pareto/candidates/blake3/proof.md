# Sparse-checkpoint salted rho for complete BLAKE3-r3

1. Scope and result. This is a classical ordinary collision construction for
complete unkeyed BLAKE3 with prefix rounds 0,1,2 in every compression. It uses
one explicit fixed-target heuristic H-checkpoint256. Conditional on that premise,
its success probability is at least 0.39. Its deterministic total work is below
2^128.44 selected-target compression units, including failures, and all memory
is at most 2^20 bytes. Consequently its normalized time-memory cost is 128.44.
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
record uses two 32-byte RAM words. Maintain additionally two separate one-word Eytzinger arrays K and J, for keys and orbit indices respectively. Together these arrays are called E. Its occupied
indices are 1 through n, in the complete binary tree heap layout. Assign sorted
records to this tree by inorder traversal, so every left subtree key is less
than its parent and every right subtree key greater. Rebuild E after every
insertion. Exact deterministic lookup follows child indices 2*i or 2*i+1;
it returns the same orbit index as sorted lookup. Insert sorted records by
shifting, preserving order. Both insertion and rebuild have finite charges
below. No randomized hash table or expected lookup bound is used.
Only checkpoints, not all intermediate orbit states, are retained.

4. Concrete detection and recovery controller. Initially C[0]=x0 and the sorted
array contains (x0,0). Set x=x0. Execute the following finite loops, with bounds
and all failure paths exactly as specified. A lookup returns an exact matching
state's index or NONE; it never tests only a digest projection in the full attack.

    for j = 1,...,B:
        x = f_S(x)
        k = eytzinger_lookup(x)
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
The chronological array and sorted records hold at most 4097 checkpoints:
index 0 and positive multiples of D through m. At the terminal j=m+D no
insertion occurs. The Eytzinger tree has at most 13 occupied levels because
floor(log2(4097))+1=13; conservatively charge 14 iterations including the
terminal failed range check. Search uses the following explicit RAM routine.
K and J are separate contiguous one-word arrays. K[i] is the key and J[i] its orbit index. A word address is base+i; each lookup iteration charges this addition explicitly.

    i=1
    while i<=n:
        y=K[i]
        if x==y: return J[i]
        if x<y: i=i<<1
        else: i=(i<<1)+1
    return NONE

An occupied iteration costs at most 11 primitive operations: range comparison
and branch (2), key address calculation (base+i, 1), key load (1),
equality comparison and branch (2), order comparison and branch (2), child
shift and optional add (2), loop jump (1). Indices and bases are RAM words;
no multiplication primitive is assumed. Return-index address calculation and
load, initialization and NONE/return routing are paid from the 64-operation
nonsearch allowance specified in section 13. A terminal range check costs
only two operations and is safely included as one whole iteration. Thus lookup
costs at most 154 operations, and the full detection step at most 218,
below an adopted ceiling of 224 per target call. Recovery retains its independent
128-operation allowance and fits the same ceiling.

Each sorted insertion shifts at most 4097 two-word records, at 32 operations
per record plus 512 setup/append operations. Rebuild E deterministically by
an inorder traversal of the implicit occupied heap indices 1..n. On entry to
a node, recurse to 2*i if in range, copy the next sorted key and orbit index into K[i] and J[i],
then recurse to 2*i+1 if in range. Use an explicit stack of at most 14 frames,
each containing node index and traversal phase. Child arithmetic uses shifts
and additions. A generous 256 operations per visited node covers traversal,
stack operations, bounds tests and the two-word copy. With at most 4097
insertions and at most 4097 nodes per rebuild, all insertion/rebuild work is
less than (32+256)*4097^2+512*4097 <2^33 word operations.
Initialization, true random words, output, final verification adapters and
finite preliminary research are included in the unchanged larger fixed
allowance 2^40. Thus deterministically for every random choice,
    W <=224*(m+4D+2)+2^40,
    T = H+W/638
      <=(1+224/638)*(m+4D+2)+2^40/638
      <1.353*2^128+2^32 <2^128.44.
The exact leading coefficient is (1+224/638)*(1+4/4096), approximately
1.35242; 2^0.44 exceeds 1.356. The positive slack covers the fixed allowance.
There are no restarts, hidden failure trials or unpriced table operations.
The fixed allowance in compression units is below 2^31. This is total RAM
work, not Python runtime or processor latency.

11. Memory ledger. Chronological checkpoints use 4097*32=131104 bytes;
sorted two-word records use 4097*64=262208 bytes; the Eytzinger array with
an unused index zero in each of K and J uses 2*4098*32=262272 bytes. Sum: 655584 bytes. Reserve
65536 bytes for uniform code/constants and 8192 for live words, compression
workspace, buffers and stack, including 14 rebuild frames of two words each.
Total 729312 bytes, below 1048576. Rebuild reads the sorted array and writes
E directly without an additional array. Insertions use two temporary words.
There is no orbit history, advice, runtime allocation or unrolled long loop.
Memory_log2_bytes=20 is conservative, so normalized cost equals raw time
128.44. The extra Eytzinger storage remains below the one-MiB floor.

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

13. Nonsearch control allowance and provenance. This revision directly builds
on aebd6cd3-a42e-4762-94f9-4559a7badedb (which itself builds on f6a36631-f9ca-4652-ac44-1fdb24d23dcb), retaining its orbit
controller, exact complete target injection, sufficient event, probability
premise, recovery and all four experiment source/manifest bytes. It replaces
only lookup representation and its finite cost ledger. The inherited 64-word-
operation detection allowance is retained with its explicit breakdown:
12 for input/output buffers and target argument setup; 8 for orbit counter,
cap and loop routing; 8 for checkpoint-mask tests; 12 for search initialization,
return-index address/load and NONE/hit routing; 8 for pointer/register updates
and count access; 16 spare for literals, addressing and control transfers.
Its former binary-search bound is replaced by section 10's 154-operation
bound, giving 218 <=224. Fixed target metadata and buffer bases are initialized
once. The compression primitive's internals are charged by H, not discounted.
Recovery keeps the source's 128-operation bound and fits 224 per call.
Insertion and rebuilding are separately covered by the fixed allowance.
The unchanged finite probes use sorted lookup, which is extensionally identical
to Eytzinger lookup: inorder assignment preserves strict search ordering, and
both return exactly the unique checkpoint with key x or NONE. Thus their
controller behavior is unchanged; they do not benchmark the new RAM lookup or
verify its instruction count. No local finite result or full-width run is
claimed. Lookup correctness and cost are supported by the explicit tree and
RAM arguments above, rather than a measured runtime claim. The score-critical
full-width orbit heuristic remains unresolved. Earlier source attributions in
section 12 identify retained material; this revision asserts no new differential
cryptanalysis, unconditional collision bound, or human acceptance.

14. Split-array revision. The immediate source used interleaved key/index records. This revision uses separate contiguous key and index arrays, saving one address arithmetic operation per visited search node. The heap ordering, exact hit result and controller are unchanged. Both arrays together occupy exactly the former record storage. The rebuild allowance already pays for separate addresses. This is a resource-ledger improvement conditional on the same unresolved full-width heuristic, with no new measured cryptanalytic evidence.
