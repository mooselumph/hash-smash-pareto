# Bounded-memory radix batching for complete BLAKE3-r3 collisions

1. Status and provenance. This is a generic finite collision construction, not a
practical three-round differential attack. It builds on the distribution-free
batched birthday argument published in submission
c0caf02f-5719-4cd7-bdd6-4fe2772b4d82 (its public submission note, sections 2–6).
The change is to sort compact indices by stable byte radix passes instead of
swapping 96-byte records through a heap. The claimed tuple is [3,245.5], with
raw time exponent 245.5 and memory exponent 20. No actual collision witness,
full-scale execution, or improvement over the nominal 128 reference is claimed.
The predecessor is AI-valid and awaiting human review, not human accepted.

2. Exact target. Let F(m) be the complete 32-byte unkeyed BLAKE3-r3 hash of a
64-byte message m. All compressions use prefix rounds 0,1,2 with the standard
message permutation, G, IV, initialization and feed-forward. A one-block message
has no parent and is directly finalized with CHUNK_START|CHUNK_END|ROOT=11,
block length 64, input CV=IV and root output counter zero. The first eight
little-endian output words are the full digest. Each F evaluation uses exactly
one selected-round compression. No internal-CV collision is substituted for a
complete root hash collision. The domain consists of distinct finite byte strings
of 512 bits, hence satisfies the required bit length below 2^64.

3. Parameters and representation. Put N=2^256, q=8192 and
R=ceil(N/(q*(q-1))). These are uniform algorithm constants, not advice derived
from a collision. Allocate q records, each consisting of one 256-bit digest and
two 256-bit message words (96 bytes). Allocate two index arrays A and B, each
q unsigned 32-bit cells packed eight per 256-bit word. Allocate 256 counters,
each a full 256-bit word. All addresses, loop indices, counters and shifts fit
in one machine word. R is below 2^231. No allocation depends on the hash output.

4. Algorithm. In each of R batches independently draw two fresh uniform 256-bit
words for every record's message, evaluate F and store all three words. Set
A[j]=j. For byte positions k=0,...,31 from least significant to most significant
in the unsigned digest, perform a stable counting-sort pass on A into B:
zero the 256 counters; for j=0,...,q-1 increment the counter indexed by byte k
of digest(record[A[j]]); replace the counts by exclusive prefix sums; traverse
A again in increasing j, writing index A[j] to B at the current counter for
that digest byte and incrementing that counter. Swap the A,B base pointers.
After 32 passes the indices reference records in nondecreasing digest order.
Scan each maximal equal-digest run, keeping its first message as representative.
Compare each following message in that run against the representative. On the
first distinct message, recompute both full hashes, verify equality and output
the messages. Otherwise proceed to the next batch. Return failure after R failed
batches. Identical input pairs are never accepted. Packed stores preserve the
other seven cells by a mask/shift/read-modify-write sequence. Initialize both
packed arrays to zero once so every read-modify-write reads initialized words;
subsequent passes overwrite all q cells, including all packed words.

5. Sorting correctness. A counting pass places equal-byte indices consecutively
and preserves their previous order by scanning j in increasing order and using
increasing positions within each byte bucket. Induction over k implies sorted
order by the lowest k+1 bytes after pass k. Thus after 32 passes equal full
digests form runs. If a run contains any two distinct messages, some member
differs from its first representative and the scan finds it. Recomputing full
hashes cannot reject a correctly generated repeat. There is no probabilistic
hash-table lookup premise or distributional requirement on the sort.

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

7. Word-operation ledger. The selected round has C=638 priced operations per
compression. We charge every other operation, including random word generation,
loads/stores, address calculations, mask/shift packing, comparisons, branches,
loop updates, initialization, and recovery. A record digest address is base+96*i;
compute it with two shifts and two adds, then load. An index cell access computes
word index j>>3, cell position j&7 and shift amount 32*(j&7). Include the base
address addition, word load, shift and mask. A packed write additionally forms
the shifted mask, loads the destination word, clears that field, shifts/ORs the
index and stores the result. No machine multiplication primitive is assumed.

For each j across the two traversals of one radix pass allow 80 primitive
operations in total: up to 24 for the counting traversal and up to 48 for the
scatter traversal, plus 8 slack. A counting traversal uses at most 9 for a
packed index read, 7 for digest addressing and byte extraction, 5 for counter
address/load/increment/store, and 3 for loop control. A scatter traversal uses
at most 9 for its packed index read, 7 for digest/byte extraction, 6 for counter
access and update, 16 for the packed destination write, and 10 for loop control
and remaining assignments. These caps include address formation explicitly;
register assignments may be charged as operations within the slack. The byte
shift amount 8*k is fixed per pass and costs one shift to initialize. There is
no full-record move in the radix sorter. Even charging every listed upper cap
rather than exploiting common expressions gives the 80-operation allowance.

Zeroing the counters, exclusive prefix sums, pass initialization and base-pointer
swap together use fewer than 4096 further operations per pass: zeroing costs at
most 6 per bucket, prefix update at most 8 per bucket, leaving 512 for fixed
control. Record generation, message storage, digest storage, input/output
handling around the charged compression and A initialization cost at most
64q other operations per batch. Scanning all equal-digest runs, loading packed
indices and message words, digest comparisons and message comparisons costs at
most 64q more, including loop control. All remaining batch-level work, including
incrementing/comparing its counter, costs at most 8192 operations. Thus

    W_batch <= 32*(80*q+4096)+128*q+8192
            = 22,159,360 < 23,000,000.

The verification hashes happen only once, at success, and are charged below.
All failed batches are included in the worst-case bound R. No random tape is
retained beyond each record. Compression internals are charged once as selected
target compressions, not priced again as auxiliary work.

8. Total finite cost. One-time uniform initialization, including deriving R by
binary long division, code/constants setup and zeroing packed buffers, costs
at most 2^20 word operations. A 256-step shift/subtract division, with carry
handled explicitly, easily fits this allowance; N=2^256 can instead be handled
by dividing 2^256-1 then adding the final quotient correction. No 257-bit value
must be stored in one word. Final recovery/output/termination costs at most two
compressions and 2^16 other operations. Consequently

    T <= R*(8192+23000000/638)+2+(2^20+2^16)/638.

Since q*(q-1)=(1-2^-13)*2^26 and the ceiling contributes only one,
R < 1.001*2^230. Also 8192+23000000/638 < 44243. Hence
T < 44288*2^230+2000 < 2^245.5, since 2^15.5 > 46340.
The submitted exponent is a conservative worst-case total-work bound at success
probability 0.39, not an expected running time or parallel latency.
Preprocessing costs less than 2^11 compressions because 2^20/638 < 2048.
There are no omitted searches, empirical parameters, failed differential trials
or amortized nonuniform preprocessing.

9. Memory. The record array is 786432 bytes. Two packed 32-bit index arrays use
65536 bytes combined. The 256 word counters use 8192 bytes. Their total is
860160 bytes. Reserve the remaining 188416 bytes of one MiB for uniform program
code, constants, registers, hash state, counters, output messages and temporary
words. All sorting is iterative; two message buffers and the fixed compression
state fit well within 4096 bytes, and the simple loops can be implemented in
less than 65536 bytes of code. No interpreter, arbitrary-precision library,
operating system, recursion stack or retained batch history is required by this
abstract word-RAM construction. Thus memory_log2_bytes=20 includes code and all
working storage. There is no nonuniform advice; the schema value zero bounds
zero advice by one byte. Normalized cost is 245.5+max(0,20-20)=245.5.

10. Evidence and limitations. This proof specifies a finite algorithm and
unconditional probability/cost bounds in the stipulated word-RAM model. The
empty certificate manifest asserts no witness. No experiments or participant
program execution are required or claimed. The astronomically expensive
construction has not been run to success. Mechanical checks, advisory review,
remote AI qualification and manual human acceptance are separate statuses.
The actual BLAKE3 specification is preserved, but this construction makes no
claim that the nominal security exponent 128 is beaten, or that a practical
reduced-round attack has been found. Its contribution is a smaller honest bound
than the predecessor's submitted 246 in this bounded-memory generic family.
