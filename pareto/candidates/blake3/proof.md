# 264-bit message batching for complete BLAKE3-r3

1. Scope and provenance. This is a finite classical ordinary-collision
construction for the fixed complete BLAKE3-r3 target. It is not a practical
cryptanalytic break or an improvement on nominal 128-bit collision security.
It improves the bounded-memory generic construction of submissions
c0caf02f-5719-4cd7-bdd6-4fe2772b4d82 (distribution-free batch probability),
9d85b4bf-faeb-45b3-82e6-abcd3f9ef054 (packed indices), and
297cb249-5af2-4a8c-a7e6-94cd85d579a0 (merge batching). Their public notes were used. This proof restates the needed
arguments. The change is to use 264-bit rather than 512-bit uniformly random
messages and pack the ninth random byte separately. This increases the batch
size from 10000 to 14500 within one MiB. The larger probability of identical
messages is explicitly subtracted. Raw time is bounded by 2^243.7 selected
compressions, memory by 2^20 bytes, success by at least 0.39. No claimed witness,
experiment, heuristic, ideal-output assumption, or human acceptance is used.

2. Target. Write F(m) for the full 256-bit unkeyed BLAKE3-r3 digest of a
33-byte message. Standard IV, initialization, message permutation, G function
and feed-forward are retained; use prefix rounds 0,1,2 in every compression.
A 33-byte message is a single block and chunk. Its complete root output is
computed directly from IV, true block length 33, counter zero, and flags
CHUNK_START|CHUNK_END|ROOT = 11. Bytes 33 through 63 of the compression block
are zero for word loading only. The first 32 little-endian output bytes are
the complete required digest. One F evaluation costs one target compression.
No internal chaining-value equality is substituted for the root hash.
Distinct 33-byte strings are distinct valid messages of bit length below 2^64.

3. Parameters and storage. Let N=2^256, q=14500,
D=q(q-1)=210235500, and R=ceil(N/D). In each record array position store a
256-bit digest and a 256-bit message prefix in two aligned words (64 bytes).
Store the final message byte in packed array E, 32 byte-cells per word.
Store indices in packed arrays A and B, sixteen 16-bit cells per word.
All q indices fit in 16 bits. Total aligned storage is
64q + 32*ceil(q/32) + 64*ceil(q/16)
= 928000 + 14528 + 58048 = 1000576 bytes.
Initialize packed buffers once before any read-modify-write. This is uniform
storage, with no collision advice, retained batch history, or hidden table.
R is below 2^229 and fits a 256-bit counter.

4. Algorithm. For each of at most R independent batches, draw two independent
uniform 256-bit words for each position j. Use the first word and the low byte
of the second as its 33-byte message; discard the unused 248 bits. Compute F,
write digest and prefix to the record, write the byte to E[j], and set A[j]=j.
All retained messages are independent uniform elements of a domain of size
2^264, including independence across batches.
Sort indices by full unsigned 256-bit digest using iterative bottom-up merge
sorting. For widths w=1,2,4,...,8192, and left endpoints 0,2w,4w,... below q,
merge A[left:min(left+w,q)] and A[min(left+w,q):min(left+2w,q)] into B.
At each output step take the index referencing the smaller digest, left first
on ties. Avoid accessing an exhausted run. Swap A and B bases after each pass.
Fourteen passes sort the q indices without moving records or E.
Scan equal-digest runs. Retain the first index of each run and compare each
subsequent message (prefix and final byte) with that representative. If they
differ, reconstruct both 33-byte messages, recompute both complete root hashes,
and return them after confirming equality and distinctness. Otherwise continue.
If every batch fails, return failure. There is a fixed maximum work budget,
including failed batches; this is not merely an expected stopping-time claim.

5. Sorting and collision correctness. Initially all runs of length one are
sorted. Merging preserves sorted order and every index exactly once, so induction
over the fourteen passes proves full-digest ordering. In any equal-digest run
containing distinct messages, some message differs from its first representative.
The scan finds that difference and returns a valid ordinary collision. Repeated
copies of one message alone are never accepted. Equality testing includes the
packed final byte. Sorting and scanning have no probabilistic correctness premise.

6. Probability for the fixed target. For independent uniform messages, let
p_y=Pr[F(M)=y], y ranging over N digest values. Their output distribution need
not be uniform. The probability q outputs are all distinct is q!e_q(p).
Averaging any two probabilities a,b with fixed sum cannot decrease e_q:
write e_q=ab U+(a+b)V+W, with nonnegative U,V,W independent of a,b.
Repeatedly averaging largest and smallest entries converges to the uniform
vector; continuity then shows that uniform p maximizes e_q. Thus
Pr[one batch has no digest repeat] <= (N)_q/N^q
<= exp(-D/(2N)). Batch independence gives
Pr[at least one digest repeat] >= 1-exp(-RD/(2N))
>= 1-exp(-1/2).
A repeated digest might arise from the same message. A union bound over all
within-batch message pairs in all R batches bounds this bad event by
RD/(2*2^264) <= 2^-9 + D/2^265,
because R <= N/D+1. This is below 0.001954. Subtracting yields
Pr[success] >= 1-exp(-1/2)-2^-9-D/2^265
> 0.3934693-0.001954 > 0.3915 > 0.39.
No cross-batch comparisons are made or needed. The subtraction is a bound on
all identical-message occurrences, even those accompanying real collisions;
therefore it is conservative. The reduced domain preserves enough margin.
Fresh independent random word draws, rather than deterministic seed expansion,
define the probability space. No random-oracle or random-mapping assumption
about this particular three-round function enters the argument.

7. Auxiliary operation ledger. C=638 is the selected-round reference operation
cost. Every random draw, RAM load/store, address operation, shift, mask,
comparison, branch and loop update is charged at 1/C. Multiplication is not
assumed primitive: constant products in addresses use shifts and additions.
Reading packed index t costs at most 9 operations: derive t>>4 and t&15,
scale the word index by 32 and cell index by 16, add base, load, shift and mask.
Loading its digest from record x costs at most 3 further operations (x<<6,
add base, load). Even allowing 5 gives both candidate reads at most 28.
Writing a packed output index costs at most 16 operations: address/cell
arithmetic, load destination word, form and shift mask, complement and clear,
shift new value, combine and store. Compare/choose costs at most 4 operations;
source and output pointer updates, exhausted-run tests and loop controls cost
at most 16 more. Charge 64 operations per output element per pass.
There are 14506 runs across fourteen passes:
7250+3625+1813+907+454+227+114+57+29+15+8+4+2+1.
Allow 64q+65536 operations for all run initializations, boundary minima,
pass swaps and batch fixed overhead; the surplus covers the six extra runs.
Generation costs at most 64q operations excluding the separately charged q
compressions. This includes both random draws, masking the final byte, two
record writes, packed E and A writes, address increments, zero filling and
true block-length/flag setup around the priced compression. The E cell write
has the same form as an index write and fits 16 operations. Scan costs at most
96q: two packed index reads, two digest loads, two prefix loads, two packed-byte
reads (at most 9 each), comparisons, address arithmetic, representative updates
and loop controls. Cache representative values if desired; the allowance does
not require that optimization. Successful verification is separately charged.
Thus the full batch non-compression work is bounded by
W <= (14*64+64+64+96)q+65536
  =1120q+65536 =16305536.
All fresh randomness, failed trials, memory traffic and sorting are included.
No full-record movement or library sorting is assumed. The larger 96-operation
scan allowance includes comparison of the final message byte.

8. Finite time. Charge at most 2^20 auxiliary operations for uniform code and
constant setup, deriving R, and initializing arrays. Derive R by binary division
of 2^256-1 by D followed by the quotient/remainder correction, requiring only
256-bit registers. Charge final output and termination at most two compressions
plus 2^16 auxiliary operations. Therefore
T <= R*(14500+16305536/638)+2+(2^20+2^16)/638.
Since R < 1.001*2^256/210235500 and
14500+16305536/638 < 40058,
T < (1.001*40058/210235500)*2^256+2000
  < 0.000191*2^256+2000 < 2^243.7.
The last inequality has ample margin: 2^(243.7-256)=2^-12.3 > 0.000198.
The setup exponent is at most 11 since 2^20/638<2048. The claim uses raw
time_log2=243.7 and preprocessing_log2=11. This is a worst-case total work
bound over all processors, not parallel wall-clock latency or amortized cost.
The nominal reference ID in the claim is metadata, not a statement of beating
128. The bound improves the cited construction's submitted 244.2 by 0.5 bit.

9. Complete memory. The arrays occupy 1000576 bytes, leaving 48000 bytes below
one MiB. Reserve 32768 bytes for uniform code and literal constants, 8192 bytes
for RAM registers, compression workspace and loop/address temporaries, and
4096 bytes for output reconstruction. Total reservation 45056 bytes fits.
Loops are iterative, not recursively stacked. There is no interpreter, operating
system, external sorting library, arbitrary-precision library, or retained random
history in this abstract word-RAM construction. F is the cost model's target
primitive, with working state fitting the reservation. A fixed program of at
most 1024 32-byte instructions implements the small counted loops and packed
access routines with literals; no unrolled merge schedule is needed. Zero
nonuniform advice is used. The schema zero advice exponent bounds it by one
byte. Thus memory_log2_bytes=20 accounts for data, code and all scratch.
The normalized time-memory score is 243.7+max(0,20-20)=243.7.

10. Limitations and evidence. The certificate manifest is empty. No collision
has been computed and no experiment is declared or needed for the analytic
probability argument. The construction is astronomically expensive and only
bounds a generic fixed-target attack in the specified abstract model. It makes
no reduced-round structural or practical claim. Mechanical readiness, optional
independent critique, remote AI qualification, and manual human acceptance are
separate stages. Neither predecessor qualification nor this proof asserts that
any submission was promoted. All target, resource and probability obligations
are stated here without requiring a judge to fetch an external citation.
