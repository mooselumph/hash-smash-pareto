# Sparse-checkpoint salted rho for complete BLAKE3-r3

1. Scope and result. This is a classical ordinary collision construction for
complete unkeyed BLAKE3 with prefix rounds 0,1,2 in every compression. It uses
one explicit fixed-target heuristic H-checkpoint256. Conditional on that premise,
its success probability is at least 0.39. Its deterministic total work is below
2^128.36 selected-target compression units, including failures, and all memory
is at most 2^20 bytes. Consequently its normalized time-memory cost is 128.36.
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
record uses two 32-byte RAM words. Maintain two separate one-word Eytzinger arrays K and J, each with slots
0..8191. Their occupied heap indices 1..8191 form a perfect depth-13 tree.
Assign the n real sorted records first in inorder, followed by 8191-n padding
records with key U=2^256-1 and index NONE. A real key U precedes all padding.
K holds keys and J holds orbit indices. Rebuild after every insertion.
Section 10 specifies a lower-bound lookup that returns the unique real exact
match or NONE, even for key U. Insert sorted records by shifting in place.
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

10. Deterministic total-work ledger and exact lookup. C=638 word operations
per selected target compression. Detection uses at most m+D target calls;
right reconstruction fewer than D; synchronous recovery at most 2D; final
verification at most two. Thus H<=m+4D+2 for every random choice and failure.
There are at most 4097 real checkpoint records, including index zero. No record
is inserted at the terminal j=m+D. Padding fills the perfect tree to 8191 nodes.

Lookup first sets i=1 and executes the following five operations exactly thirteen
times, with thirteen explicit straight-line copies, so no loop test or jump:

    addr = baseK+i
    y = LOAD(addr)
    b = (y < x)                 # comparison returns word 0 or 1
    i = i << 1
    i = i + b

The resulting external-leaf index is in [8192,16383]. Each left edge means the
parent key was >=x; each right edge means it was <x. The deepest ancestor from
which the path took a left edge is the inorder lower bound, if one exists.
Delete all terminal right edges and the preceding left edge to obtain it.
For an all-right path the answer is index zero, meaning no lower bound.
Compute z=(NOT i) AND (i+1), with three priced word operations. Its sole set bit
has index t equal to the count of trailing one bits in i. Here 0<=t<=14.
Find t with four fixed stages, using the following small-word binary search:

    t=0; v=z
    for q in [8,4,2,1]:
        if v >= (1 << q):
            v = v >> q
            t = t + q
    a = i >> (t+1)

The four stages are emitted straight-line with literal thresholds 256,16,4,2.
Each stage costs at most four operations: comparison, branch, shift, add.
The three operations to form z, two initial assignments, sixteen stage operations,
and the final add and shift cost at most 23 operations. Lookup then checks a=0
(comparison and branch), loads K[a] (address and load), tests equality to x
(comparison and branch), and on equality loads J[a] (address and load).
Returning NONE or the loaded index is covered by the separate routing allowance.
Thus initialization of i (one), descent (65), decoding (23), and final checks
(eight) cost at most 97 operations, conservatively rounded to 104.

Correctness: along the search path all keys passed by a right edge are <x and
cannot be a lower bound. A key passed by a left edge is a candidate >=x, and
each later left edge supplies a candidate earlier in inorder. Hence the last
left parent is the first inorder key >=x. A real exact key, including U, occurs
before any equal padding, so if an exact real key exists this first key is real
and J returns its index. If the lower bound is padding, J returns NONE; if its
key is greater than x, the equality check returns NONE. The all-right case also
returns NONE. Therefore lookup is extensionally identical to the inherited exact
sorted search, with no additional heuristic or failure event.

Add the inherited 64-operation nonsearch controller allowance from section 13:
104+64=168. Adopt a common ceiling of 176 operations per target call, also
covering recovery's unchanged 128-operation allowance. No native multiplication,
ctz instruction, conditional move or unpriced table access is assumed.

Each sorted insertion shifts at most 4097 two-word records, at 32 operations
per record plus 512 setup/append operations. Rebuild traverses all 8191 nodes
inorder with an explicit stack of at most 14 two-word frames. Copy the next
real sorted record if available, otherwise write literal (U,NONE). At most
256 operations per node covers traversal, addresses, tests, both stores and
stack maintenance. Across at most 4097 rebuilds the bound is
    4097*(32*4097+512+256*8191) < 2^34 word operations.
The fixed allowance 2^40 covers this, initialization, two uniform random words,
output, final verification adapters and finite preliminary research. Thus
    W <=176*(m+4D+2)+2^40,
    T = H+W/638
      <=(1+176/638)*(m+4D+2)+2^40/638
      <1.278*2^128+2^32 <2^128.36.
Indeed the leading coefficient is (1+176/638)*(1+4/4096)<1.278,
whereas 2^0.36>1.283. Positive slack covers all fixed charges.
All trials and failures are charged; there are no restarts. This is total work,
not wall time. The fixed allowance in compression units is below 2^31.

11. Memory ledger. Chronological checkpoints use 4097*32=131104 bytes;
sorted two-word records use 4097*64=262208 bytes. K and J each have 8192 slots,
including unused index zero: together 2*8192*32=524288 bytes. Sum: 917600 bytes.
Reserve 65536 bytes for uniform code/constants and 8192 for live words,
compression workspace, buffers and the 14-frame rebuild stack. Total 991328
bytes, below 1048576. The thirteen five-operation descent copies are finite
small code included in that reserve, not an unrolling of the orbit loop.
Rebuild reads sorted records and writes K,J directly without extra arrays.
Insertions use temporary words within the workspace. No advice, orbit history
or hidden allocation is retained. memory_log2_bytes=20 is conservative, hence
normalized time-memory cost equals raw time exponent 128.36.

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
on 473f2d01-7012-45be-89f9-3f350b6ecf75. It retains the exact complete target,
salt injection, orbit controller, sufficient success event, random-map argument,
full-width premise H-checkpoint256, recovery and all four experiment manifest
and source bytes. The predecessor in turn builds on aebd6cd3-a42e-4762-94f9-4559a7badedb,
f6a36631-f9ca-4652-ac44-1fdb24d23dcb and earlier work attributed in section 12.
The inherited 64-operation detection allowance is retained: 12 for input/output
buffers and target argument setup; 8 for orbit counter, cap and loop routing;
8 for checkpoint-mask tests; 12 for search return and NONE/hit routing;
8 for pointer/register updates and count access; 16 for literals, addressing
and control transfers. Lookup initialization, addresses, key comparisons,
index decoding and J loads are already charged explicitly in section 10.
104+64=168<=176. Recovery's inherited 128-operation allowance also fits 176.
The compression primitive internals are charged by H, never discounted.
Insertion, padding and rebuilding are separately charged to fixed work.

The finite probes retain sorted lookup. Section 10 proves identical returned
indices for the new padded lower-bound tree, including equality at the largest
word and padding. Thus controller behavior is identical, though the probes do
not measure or empirically verify the new RAM instruction count. No local
experiment result or full-width execution is asserted. This is a deterministic
resource improvement conditional on exactly the inherited unresolved heuristic;
it supplies no new differential, full-width evidence or human acceptance.
