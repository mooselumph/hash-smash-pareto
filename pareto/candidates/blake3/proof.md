# Bounded-memory merge batching for complete BLAKE3-r3 collisions

1. Status and provenance. This is a generic finite collision construction, not a
practical three-round differential attack. It builds on the distribution-free
batched birthday argument published in submission
c0caf02f-5719-4cd7-bdd6-4fe2772b4d82 (public note, sections 2–6), and on our
packed-index representation introduced in submission
9d85b4bf-faeb-45b3-82e6-abcd3f9ef054. Instead of radix sorting, use bottom-up
merging of packed 16-bit indices. Increase the batch from 8192 to 10000 while
keeping records word-aligned. The claimed tuple is [3,244.2], with raw time
exponent 244.2 and memory exponent 20. No actual witness or practical execution
is claimed. Predecessor AI qualification and human acceptance are distinct.

2. Exact target. Let F(m) be the complete 32-byte unkeyed BLAKE3-r3 hash of a
64-byte message m. All compressions use prefix rounds 0,1,2 with the standard
message permutation, G, IV, initialization and feed-forward. A one-block message
has no parent and is directly finalized with CHUNK_START|CHUNK_END|ROOT=11,
block length 64, input CV=IV and root output counter zero. The first eight
little-endian output words are the full digest. Each F evaluation uses exactly
one selected-round compression. No internal-CV collision is substituted for a
complete root hash collision. The domain consists of distinct finite byte strings
of 512 bits, hence satisfies the required bit length below 2^64.

3. Parameters and representation. Put N=2^256, q=10000 and
R=ceil(N/(q*(q-1))). These are uniform algorithm constants, not collision advice.
Allocate q records, each with one 256-bit digest and two 256-bit message words,
96 bytes total. Two index arrays A and B have q unsigned 16-bit cells each,
packed sixteen per 256-bit word. No sorting counters or other tables are needed.
All loop indices, addresses and R fit one word; R is below 2^231. Initialize
both packed arrays once so read-modify-write never reads uninitialized storage.
Every subsequent complete pass overwrites all q cells.

4. Finite algorithm. Each batch independently generates q uniform 512-bit
messages using two fresh independent random word draws per record. Evaluate F,
store the digest and message, and set A[j]=j. For run widths w=1,2,4,...,8192,
merge consecutive sorted runs of A into B by unsigned full 256-bit digest:
for left=0,2w,4w,... below q, set mid=min(left+w,q), end=min(left+2w,q),
i=left,j=mid. For output positions k=left,...,end-1, select A[i] if the right
run is exhausted, A[j] if the left run is exhausted, and otherwise compare the
two referenced digests and select the smaller (left on ties). Write the chosen
index into B[k] and increment its source pointer. After all runs swap A and B
base pointers, double w, and stop once w>=q. Fourteen complete merge passes
suffice. Packed stores mask only their destination cell and preserve the others.
Scan the resulting index array by equal-digest runs. Keep the first message
of each run and compare every following member to it; on finding a distinct
message recompute both complete root hashes and output them after verification.
Otherwise proceed to the next batch. Return failure after R failed batches.

5. Correctness. A width-w merge combines two sorted runs into a sorted run of
length at most 2w. At width 1 every input run is trivially sorted. Induction over
fourteen passes therefore gives nondecreasing full-digest order, including the
short final runs. Every record index occurs exactly once. If an equal-digest
run contains distinct messages, at least one differs from its representative,
and the scan finds it. Identical inputs are never accepted. Recomputing hashes
cannot reject correctly computed distinct-message equality. The sorter has no
probabilistic or hash-output-distribution premise.

6. Probability, inherited argument made explicit. For independent uniform
512-bit messages let p_y=Pr[F(M)=y]. The probability q independently sampled
digests are all distinct equals q! e_q(p), where e_q is the elementary symmetric
polynomial. For fixed sum of any two coordinates a,b, write e_q=ab U+(a+b)V+W,
with U,V,W nonnegative and independent of a,b. Averaging a,b cannot decrease
this expression. Repeated averaging of largest and smallest coordinates
converges to the uniform vector, and continuity gives that uniform p maximizes
the no-repeat probability. Hence for this fixed target, even with biased output,

    Pr[no digest repeat in one batch] <= (N)_q/N^q
      <= exp(-q*(q-1)/(2*N)).

Fresh independent batch coins imply that at least one within-batch digest repeat
occurs with probability at least 1-exp(-R*q*(q-1)/(2*N)) >= 1-exp(-1/2).
The probability of any identical-message pair within any of the R batches is
at most R*q*(q-1)/(2*2^512), by a union bound. Since
R <= N/(q*(q-1))+1, this is at most
2^-257+q*(q-1)/2^513 < 2^-256. Subtracting this event leaves success at least
1-exp(-1/2)-2^-256 > 0.3934 > 0.39. There is no union bound across distinct
batches because only within-batch comparisons are used. The sorting change
preserves exactly this event. No random-oracle or ideal-output heuristic is used.

7. Word-operation ledger. The selected-round contract has C=638. Every
auxiliary random draw, memory access, address calculation, shift/mask, comparison,
branch and loop update is charged. Reading index cell t requires computing
u=t>>4, v=t&15, shift=16*v, address=base+32*u, loading the word, shifting and
masking: at most 9 operations, including all address arithmetic. Accessing a
record digest from index x costs two shifts, two additions (base+96*x), and a
load, at most 5 further operations. Thus reading and dereferencing both merge
candidates costs at most 28 operations. A packed destination write uses at most
16 operations: compute destination word address and bit shift, load the word,
form and shift a 16-bit mask, NOT/AND to clear the cell, shift and OR in the
selected index, and store. There is no multiplication primitive hidden here.
Comparison and choice use at most 4 operations. Run-boundary tests, source
pointer increment, output pointer increment and loop control use at most 16
more. This totals at most 64 operations per output element per merge pass.
Exhausted-run iterations only need one candidate and also fit that bound. Avoid
unnecessary candidate loads once a run is exhausted. Digest ties choose the
left candidate without another comparison. Register copies fit the allowance.

The algorithm performs exactly q output writes in each of fourteen passes.
Run initialization, boundary minima and run-loop control cost at most 64
operations per run. There are
5000+2500+1250+625+313+157+79+40+20+10+5+3+2+1=10005
runs across all passes. Charge 64q operations for their setup and reserve a
further 65536 for the five extra runs, pass-level swaps, counters and all fixed
batch overhead. Generation, record stores, A initialization and handling around
the already charged compression take at most 64q operations. A complete scan
costs at most 64q, including packed accesses, digest loads, both two-word message
comparisons, run representative updates, loop controls and success checks.
Output recovery and the two final verification compressions are charged once
below. Thus the full non-compression batch ledger is

    W_batch <= 14*64*q + 192*q + 65536
            = 10,945,536 < 11,000,000 operations.

There is no full-record copy during sorting. Initial message and digest writes
are already included in generation. Only the packed index arrays are written
per pass. All failed batches and all fresh random words are included. Hash
compression internals are charged once, not double-counted as auxiliary work.

8. Total finite cost. One-time uniform initialization, including deriving R,
program/constants setup and zeroing the two index arrays, costs at most 2^20
word operations. Binary long division needs only 256 shift/subtract iterations;
handle N using 2^256-1 followed by the quotient/remainder correction, so no
257-bit register is assumed. Recovery/output/termination takes at most two
compressions and 2^16 further word operations. Consequently

    T <= R*(10000+11000000/638)+2+(2^20+2^16)/638.

Here q*(q-1)=99,990,000. Including the ceiling,
R < 1.001*2^256/100,000,000, and
10000+11000000/638 < 27242. Thus
T < (1.001*27242/100000000)*2^256+2000 < 2^244.2.
For a direct numerical margin, 1.001*27242/100000000 = 0.00027269242,
whereas 2^(244.2-256) = 2^-11.8 > 0.0002804. The additive 2000 fits this
strict margin. The exact unrounded logarithm of the batch expression is about
244.1583, and the submitted 244.2 is an upper bound, not an expected runtime.
Preprocessing is below 2^11 compression equivalents, since 2^20/638<2048.
No parallel-latency discount, amortized preprocessing, omitted construction
search, collision advice or empirical extrapolation enters this ledger.

9. Memory. The q=10000 record array uses 960000 bytes. Each packed index buffer
uses 20000 bytes, exactly 625 full words. Total arrays occupy 1000000 bytes,
leaving 48576 bytes below one MiB. Reserve 32768 bytes for uniform program code
and literals, 8192 for registers, complete root-compression state, loop counters,
constants and address scratch, and 4096 for output messages/recovery. Their sum
45056 fits the 48576 remainder. The fourteen passes and all merges are iterative;
there is no recursion, operating system, interpreter, sort library, retained
history or arbitrary-precision library in this abstract RAM implementation.
The small counted loops need no unrolled code; 1024 fixed instructions at a
32-byte instruction encoding suffice for the 32768-byte code allocation, with
the fixed IV and q,R constants in its literal allowance. Hash evaluation is the
model's priced target operation and its small state fits the reserved 8192.
Thus memory_log2_bytes=20 bounds program plus data. Nonuniform advice is absent
(the schema value zero bounds zero by one byte). The scalarized cost is exactly
244.2+max(0,20-20)=244.2.

10. Evidence and limitations. This proof specifies a finite algorithm and
unconditional probability/cost bounds in the stipulated word-RAM model. The
empty certificate manifest asserts no witness. No experiments or participant
program execution are required or claimed. The astronomically expensive
construction has not been run to success. Mechanical checks, advisory review,
remote AI qualification and manual human acceptance are separate statuses.
The actual BLAKE3 specification is preserved, but this construction makes no
claim that the nominal security exponent 128 is beaten, or that a practical
reduced-round attack has been found. Its contribution is a smaller honest bound
than the predecessors' submitted 246 and 245.5 in this bounded-memory generic family.
