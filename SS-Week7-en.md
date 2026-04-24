---

tags:

- security
- side-channel
- timing-attack
- meltdown
- spectre
- cryptography
- cpu-architecture

---

# Side-Channel Attacks

## Overview

**Side-channel attacks** are a class of attacks that exploit **information leaked from the execution process** of a system — rather than from weaknesses in algorithms or protocols. This is what makes them particularly dangerous: a system may implement a cryptographic algorithm that is mathematically perfect, but the way it runs on actual hardware leaks the secret key through timing, power consumption, or electromagnetic emissions. This lecture analyzes two important case studies: **Timing Attack on RSA/OpenSSL** (Brumley & Boneh, 2003) and two historic CPU vulnerabilities **Meltdown & Spectre** (2018).

---

## Detailed Content

### 1. Side Channel Concepts

#### 1.1 Definition

A **side channel** is an **unintended** information channel arising from the physical execution of a computer system:

- Timing information (execution time)
- Power consumption
- Electromagnetic emissions
- Acoustic emanations
- Cache behavior

**Side-channel attack**: an attack based on information collected from these channels — exploiting not the weakness in the algorithm, but the way the algorithm is **implemented**.

> [!note] Covert Channel — A Related Concept A **covert channel** is an information channel that is **not supposed to exist** in a system. Example: a process at a high security level "leaks" secrets to a low security level process by manipulating CPU or cache usage — something the second process can observe.

#### 1.2 Attack Model

```
         Functional interactions
User ←────────────────────────→ System
                                    ↑
                                    │ (attacker can also
    Attacker ←·····················│  modify/influence
    (observes)  Side channel:      │  the system)
                power, EM,         │
                acoustic, timing···┘
```

- **Passive attacker**: only observes the side channel (e.g., measuring timing remotely)
- **Active attacker**: both observes and **interferes with/influences** the system (e.g., sending ciphertext to measure response time)

> [!question] Why do side-channels often target cryptographic constructions? Because this is where **secret data (private key, secret key)** is processed most frequently. If the attacker learns the private key, the entire system's security collapses. Moreover, cryptographic operations often have timing/power behavior that depends on data — creating ideal conditions for side-channel attacks.

#### 1.3 History: TEMPEST (since 1943)

**TEMPEST** (Telecommunications Electronics Materials Protected from Emanating Spurious Transmissions) was an NSA research program on electromagnetic emanations from electronic devices. Discovered during WWII: the Bell 131B2 mixer (using XOR of teleprinter signal with one-time tape) emitted electromagnetic signals reflecting the plaintext — detectable from a distance.

This is the earliest historical evidence that side channels are a practical problem, not just theoretical.

---

### 2. Common Types of Side-Channel Attacks

#### 2.1 Power-Monitoring Attack

**Principle**: The power consumption of hardware **depends on the instruction being executed** and the data being processed. Attackers measure power consumption fluctuations using an oscilloscope.

**Simple Power Analysis (SPA)**: Observing a single execution run to distinguish different operations (e.g., bit 0 vs bit 1 in RSA square-and-multiply).

**Practical setup**:

```
Cryptographic device (e.g., smart card)
         │
         │ Control + Ciphertext
         ▼
    Smart card reader ────── Oscilloscope ────── Computer
                                  ↑
                            Measure power
                            waveform
```

A graph of actual power consumption per clock cycle can directly reveal each bit of the secret key in some naive implementations.

> [!example] DPA — Differential Power Analysis A more advanced technique than SPA: measure **many runs**, apply statistical analysis to filter noise and extract key information, even when a single trace is not clear enough.

#### 2.2 Timing Attack

**Principle**: The execution time of an operation depends on the **value of the input/key** — the attacker measures time to infer secret information.

**Two types:**

|Type|Characteristics|Difficulty|
|---|---|---|
|**Local timing attack**|Attacker on the same machine, precise measurement|Easier to perform|
|**Remote timing attack**|Measured over network|Must eliminate network jitter: `exec_time = total_time − network_latency − other_noise`|

> [!note] Are Remote Timing Attacks Feasible? Yes — this has been proven in practice. With a sufficient number of samples and statistical analysis, a weak timing signal from afar can still be extracted. The paper by Brumley & Boneh (Usenix Security 2003) is the clearest demonstration.

---

### 3. Case Study: Timing Attack on OpenSSL RSA

_(Based on the paper: "Remote Timing Attacks are Practical" — Brumley & Boneh, Usenix Security 2003)_

#### 3.1 Background: RSA Cryptosystem

**RSA** is a public-key cryptosystem based on the large integer factorization problem.

**Key Generation:**

1. Choose two large primes **p** and **q**
2. Compute `n = p × q` (modulus)
3. Compute `φ(n) = (p−1)(q−1)` (Euler's totient)
4. Choose `e` coprime with `φ(n)` → **public key exponent**
5. Compute `d` such that `e·d ≡ 1 (mod φ(n))` → **private key exponent**

**Public key**: `(e, n)` | **Private key**: `(d, n)` _(or `(d, p, q)` in practice)_

**Encrypt/Decrypt:**

```
Encrypt:  c = mᵉ mod n
Decrypt:  m = cᵈ mod n
```

**Toy example:**

```
p=5, q=3 → n=15, φ(n)=8, e=3, d=3
Encrypt m=2: c = 2³ mod 15 = 8
Decrypt c=8: m = 8³ mod 15 = 512 mod 15 = 2 ✓
```

> [!note] OAEP Padding In practice, message M is padded before encryption using **Optimal Asymmetric Encryption Padding (OAEP)**: adding a known pattern + random number. Reason: plain RSA is **multiplicative** (c₁·c₂ = encrypt(m₁·m₂)) and **deterministic** (same m yields same c) — OAEP solves both issues.

#### 3.2 OpenSSL RSA Implementation — Two Sources of Timing Leak

**OpenSSL performs RSA decryption using the Chinese Remainder Theorem (CRT):**

```
mₚ = cᵈ mod p
m_q = cᵈ mod q
m = CRT(mₚ, m_q)
```

Computing `cᵈ mod q` requires **modular exponentiation** — this is where the timing leak occurs.

---

**Source 1: Montgomery Reduction — Extra Reduction**

**Montgomery Reduction** is an algorithm for performing modular reduction more efficiently than regular division. The idea: convert to reduction modulo a _power of 2_ (implemented via bit shift, very fast).

**Montgomery Form:**

```
a  →  a' = aR mod q   (R is a power of 2)
b  →  b' = bR mod q
c = ab  →  c' = MM(a', b') = a'b'/R mod q
```

**Montgomery Multiplication (MM) algorithm:**

```
z = 0
for i = w-1 to 0:
    z = z + xᵢ * y
    if z is odd: z = z + q    ← conditional extra reduction!
    z = z / 2                  ← cheap bit shift
if z >= q: z = z - q          ← conditional extra reduction!
```

**Timing leak**: the step `if z is odd: z = z + q` is **input-dependent** — whether it occurs depends on the input value. Each extra reduction costs additional time.

**Werner Schindler's finding**: The probability of an extra reduction while computing `gᵈ mod q` is proportional to the distance between g and q:

```
Pr[Extra Reduction] = (g mod q) / (2R)
```

This means: if g is close to q, there are more extra reductions → execution is **slower**. This is a clear timing signal!

---

**Source 2: Multiplication Routine — Karatsuba vs Normal**

OpenSSL has two multiplication routines:

- **Karatsuba**: used when two numbers have the **same number of words** → `O(x^1.58)` (faster)
- **Normal**: used when two numbers have **different number of words** → `O(xy) ≈ O(x²)` (slower)

Multiplication accounts for approximately **40% of total RSA decryption runtime** → the choice between the two routines creates a significant timing difference.

---

**The two timing sources counteract each other:**

|Case|Montgomery Reduction|Multiplication Routine|Net Effect|
|---|---|---|---|
|`g < q`|Slower (more extra reductions)|Faster (Karatsuba)|Hard to predict|
|`g ≥ q`|Faster (fewer extra reductions)|Slower (Normal)|Hard to predict|

> [!note] Why Don't They Cancel Out Completely? Because the two effects have **different magnitudes** depending on the specific value of g and the bits of q. The attacker exploits the remaining residual difference through statistics.

#### 3.3 Attack Algorithm — Learning Each Bit of q

**Goal**: Learn the private key q, one bit at a time.

**Approach**: Assume the first i−1 bits of q are already known. To find the i-th bit:

1. Construct `g` with the same first i−1 bits as q, remaining bits set to 0
2. Construct `ghi` identical to g but with the i-th bit set to 1

**Reasoning:**

- If the i-th bit of q is 1: `g < ghi < q`
- If the i-th bit of q is 0: `g < q < ghi`

**Measurement:**

```
Construct: uₘ = gR⁻¹ mod n   (due to how OpenSSL handles Montgomery)
           u_hi = ghi·R⁻¹ mod n

Measure: t₁ = DecryptTime(uₘ)
         t₂ = DecryptTime(u_hi)
         Δ = |t₁ − t₂|
```

**Decision:**

- If `g < q < ghi` → Δ is large → bit of q is **0**
- If both g and ghi are on the same side of q → Δ is small → bit of q is **1**

**Statistical refinement** (to filter noise):

- Repeat decryption many times to reduce variance
- Query a "neighborhood" of values around g and ghi instead of just a single value

#### 3.4 Experimental Results

- Target: **OpenSSL 0.9.7**, 2.4GHz Pentium 4 machine
- Attack works in all 3 scenarios: same machine, 2 VMs, cross Ethernet LAN
- Graph (a): variance of decryption time **decreases** as sample count increases → signal converges
- Graph (b): "zero-one gap" (Δ when bit=0 vs bit=1) increases with neighborhood size → in practice ~500 queries/neighborhood is sufficient

#### 3.5 Mitigations

|Mitigation|How It Works|Limitation|
|---|---|---|
|**Use a single multiplication routine**|Eliminates one source of timing variance|May be slower|
|**Always perform extra reduction**|Eliminates the second source of timing variance|Negligible overhead|
|**Quantize execution time**|Round time → attacker cannot distinguish|Difficult to implement precisely, noise remains|
|**RSA Blinding** ✅|Before decrypt: `x = r·eᵍ mod N` (r random); after decrypt: `xᵈ/r mod N`|Small additional computation but highly effective|

> [!tip] RSA Blinding Is the Best Approach By randomizing the ciphertext before decryption, the decryption timing no longer depends on the original ciphertext value → the attacker cannot collect useful information no matter how many timing measurements they take. This is a **true cryptographic countermeasure**, not "security through obscurity."

---

### 4. Case Study: Meltdown & Spectre (2018)

#### 4.1 Background and Significance

Discovered mid-2017 by Jann Horn (Google Project Zero) and several independent groups; publicly disclosed in January 2018. Regarded as **one of the most serious bugs in the history of computing**. Impact:

- Forced redesign of CPUs, OSes, compilers, browser JavaScript JIT engines, hypervisors
- Systems suddenly became **up to 50% slower** after patching
- Affected nearly every modern CPU

#### 4.2 Background: Required CPU Architecture Knowledge

To understand Meltdown and Spectre, you need to understand why modern CPUs are so vulnerable.

**Basic CPU**: Fetch → Decode → Execute cycle. Problem: **memory access is a massive bottleneck**.

**Memory hierarchy latency** (on a 3GHz CPU, i.e., 0.3ns/cycle):

```
ALU/Registers  →  L0 cache → L1 cache → L2 cache → L3 cache → DRAM     → Storage
   ~1 cycle        ~1 cycle    ~4 cycles  ~10 cycles  ~40 cycles  200+ cycles  >>
```

If the CPU had to **stall** (pause) each time it waits for memory (200+ cycles), performance would be catastrophic. Therefore, modern CPUs have many optimizations:

**1. Out-of-order Execution**: The CPU does not execute instructions in the order written in code; instead, it rearranges them to maximize utilization of execution units while waiting for memory.

**2. Superscalar**: Multiple execution units operate in parallel.

**3. Branch Prediction**: When encountering an `if` statement, the CPU **guesses** which branch will be taken and starts executing before actually knowing the result. If the guess is correct → many cycles saved. If wrong → **rollback** to the previous state (squash transient instructions).

**4. Virtual Memory & Privilege Levels (Protection Domains)**:

```
Virtual Address Space (32-bit Linux):
┌─────────────────┐  0xFFFFFFFF
│   Kernel space  │  ← only kernel can access (ring 0)
├─────────────────┤  0xC0000000
│                 │
│   User space    │  ← user process (ring 3)
│                 │
└─────────────────┘  0x00000000
```

The CPU uses **page tables** (via MMU) to map virtual addresses → physical addresses. TLB caches these mappings. **When a user process tries to access kernel memory** → the CPU throws an exception (page fault) → the process is terminated or signaled.

> [!note] Why Is the Kernel Mapped into Every Process's Address Space? To make **system calls** faster: when a user process invokes a system call, the CPU only needs to switch privilege level (ring 3 → ring 0), without needing to completely replace page tables. If the kernel were not mapped into the user process space, every system call would require a full page table switch — very costly. This is precisely the tradeoff that led to Meltdown.

#### 4.3 Meltdown

**"Vulnerability basically melts security boundaries normally enforced by hardware."**

**Objective**: A user-space process reads **the entire kernel memory** — including passwords, keys, and memory of other processes managed by the kernel.

**Affected CPUs**: Primarily Intel (aggressive speculative execution), some ARM Cortex A-75, IBM Power.

---

**Attack mechanism — Example code:**

```c
// Naive version (what the attacker would write):
1.  s = a+b;
2.  t = s+c;
3.  u = t+d;
4.  v = u+e;
5.  if (v == 0) {
6.      w = kernel_mem[addr];   // ← FORBIDDEN: accessing kernel memory
7.      x = w & 0x01;           // ← extract 1 bit of the kernel byte
8.      y = x * 4096;           // ← multiply to align with page size
9.      z = user_mem[y];        // ← load into cache based on kernel data
10. }
```

**Problem**: Line 5 (`if v == 0`) is **always false** in all reasonable cases → the code inside the if is never executed → nothing is read.

---

**Exploiting Meltdown — Transient Instructions:**

A CPU with out-of-order execution does the following:

```c
// What the CPU actually does (parallel/out-of-order):
Sequential:              Speculative (transient):
1.  s = a+b;             w_ = kernel_mem[addr];  // CPU starts loading early!
2.  t = s+c;             x_ = w_ & 0x01;         // speculatively execute
3.  u = t+d;             y_ = x_ * 4096;         // compute y_ from kernel byte
4.  v = u+e;             z_ = user_mem[y_];       // ← LOADED INTO CACHE!
5.  if (v == 0) {
6.                        w=w_; x=x_; y=y_; z=z_; // commit if branch is correct
7.  }
// Branch is wrong → rollback: registers revert → BUT CACHE IS NOT ROLLED BACK!
```

The CPU begins **speculatively** executing inside the `if` block while the branch condition is still being computed. When it learns `v != 0` → it rolls back all register changes. **But the cache state IS NOT rolled back** — `user_mem[y_]` is still in the cache where `y_` depends on `kernel_mem[addr]`.

---

**Reading Results via Flush+Reload (Cache Covert Channel):**

```
Before running the transient code:
  → flush the entire user_mem array from cache (using clflush instruction)

After running:
  → reload each element user_mem[0], user_mem[4096], user_mem[8192], ...
  → measure reload time for each element

Result:
  → user_mem[y_] reloads faster (still in cache!)
  → y_ = (kernel_byte & 0x01) * 4096
  → from y_ we can infer at least 1 bit of kernel_byte
```

Repeat with different bitmasks (`0x02`, `0x04`, ...) → read the entire kernel byte. Repeat with different addresses → read the entire kernel memory.

> [!warning] Why Multiply by 4096? 4096 = page size. Multiplying by 4096 ensures that different y values land in **different cache lines** → distinguishable by timing. If multiplied by 1, multiple y values would fall into the same cache line → indistinguishable.

**Handling exceptions:**

The CPU throws an exception when speculatively loading kernel memory. The attacker must suppress the exception for execution to continue:

- **Exception handling**: use a `signal` handler to catch the page fault and continue
- **Exception suppression**: use hardware transactional memory (TSX) to suppress the exception within a transaction

#### 4.4 Meltdown Mitigation — KPTI

**Kernel Page Table Isolation (KPTI)** — formerly called **KAISER** (Kernel Address Isolation to have Side-channels Efficiently Removed):

**Idea**: Completely separate page tables into two sets:

```
Before KPTI:                    After KPTI:
User mode page table:           User mode page table:
┌─────────────────┐             ┌─────────────────┐
│  Kernel space   │ ← MAPPED    │  Kernel: minimal│ ← only stub for switching
├─────────────────┤             ├─────────────────┤
│  User space     │             │  User space     │
└─────────────────┘             └─────────────────┘

                                Kernel mode page table:
                                ┌─────────────────┐
                                │  Kernel: FULL   │
                                ├─────────────────┤
                                │  User space     │
                                └─────────────────┘
```

**Pros**: Addresses the root cause — user processes no longer map kernel pages → cannot speculatively access kernel memory.

**Cons**: Every **system call** or **interrupt** must switch page tables and **flush TLB** → performance hit up to **>50%** for workloads with many system calls (databases, I/O-bound).

> [!note] Intel Hardware Mitigations Intel subsequently added hardware/firmware mitigations in newer CPU generations to reduce the performance impact of KPTI. ARM and AMD CPUs are less affected by Meltdown due to their different speculative execution designs.

---

#### 4.5 Spectre (Variant 1: Bounds Check Bypassing)

Spectre **differs fundamentally from Meltdown**:

- Meltdown: user-space reads its own **kernel** memory (crosses privilege boundary)
- Spectre: the attacker tricks the **victim process itself** into reading its own memory and leaking it out (crosses process boundary or within the same process)

**Spectre affects almost all CPUs** (not just Intel) and **KPTI does not help**.

---

**Concept: Bounds Check Bypassing**

Victim code looks perfectly correct:

```c
if (x < array1_size)
    y = array2[array1[x] * 4096];
```

- `x` is a variable **controlled by the attacker**
- The bounds check (`x < array1_size`) appears safe
- But the CPU has a **branch predictor**...

---

**3 Steps of Spectre Variant 1 Attack:**

**Step 1: Train the branch predictor**

The attacker calls the code many times with `x < array1_size` (in-bounds) → the branch predictor learns: "the true branch occurs frequently" → will predict TRUE next time.

**Step 2: Supply an out-of-bounds x**

The attacker sends an `x` value that **exceeds array1_size**, pointing to secret memory within the process:

```c
x = (addr_of_secret - base_of_array1)  // out-of-bounds, but within process memory
```

The CPU speculatively executes (because the branch predictor predicts `true`):

```c
// Speculatively:
y = array2[array1[x] * 4096];  // array1[x] = secret byte!
                                 // array2[secret * 4096] is loaded into cache
```

When the CPU realizes the bounds check fails → rollback. But the cache has already been modified!

**Step 3: Read cache state**

The attacker uses **Flush+Reload** similar to Meltdown to read which value of `array2` is in cache → infer the `secret byte`.

> [!warning] Important Difference from Meltdown Meltdown reads memory that is **not permitted** (kernel space). Spectre tricks the victim into reading memory that is **permitted for the victim** (within the victim's address space) — but the attacker does not directly have that permission. This is why Spectre is much harder to mitigate.

**Real-world attack vectors:**

- **Browser JavaScript**: Microsoft PoC reads data from other tabs or browser data itself — all via JavaScript running in the browser JIT!
- **Linux kernel eBPF**: Google PoC targeting the Linux kernel packet filter

#### 4.6 Spectre Variant 1 Mitigations

|Mitigation|Mechanism|Trade-off|
|---|---|---|
|**Serializing instruction (lfence)**|Place `lfence` before bounds check → stop speculative execution|Significant performance hit; requires instrumenting all code|
|**Chrome: site isolation**|Each website in a separate process → cross-site Spectre cannot read cross-process memory|Uses more RAM|
|**WebKit: index masking**|Replace bounds check with bitwise AND with a mask → no branch to predict|Complex semantic changes|
|**Reduce JavaScript timer resolution**|Prevent attacker from measuring timing precisely → cannot perform Flush+Reload|Affects timing-dependent web apps|

> [!question] Why Is Spectre Harder to Fix Than Meltdown? Meltdown is a bug in a specific implementation (Intel's aggressive speculative execution across privilege boundaries). KPTI is a clear kernel-level fix. Spectre is a **fundamental** flaw in the design of branch prediction: speculation is needed for speed, but speculation creates a covert channel through cache. Every fix has a performance trade-off, and there is no perfect solution without changing performance.

---

### 5. Cache as a Covert Channel — Flush+Reload

Both Meltdown and Spectre use the **cache as a covert channel** to exfiltrate data. This is the **Flush+Reload** technique:

```
SENDER (transient/speculative code wanting to transmit a secret bit):
  → Load array[secret * 4096] into cache

RECEIVER (attacker code):
1. Flush: use clflush to evict array[] from cache
2. Trigger sender
3. Reload: try loading array[0], array[4096], array[8192], ...
4. Measure time for each load:
   - Cache hit (~4 cycles) → this is the index the sender loaded → this is the secret!
   - Cache miss (~200 cycles) → not it
```

**Why is cache a good covert channel?**

- Cache is **shared** between processes (and between user/kernel on the same core)
- The timing difference between cache hit/miss is very large and measurable (~196 cycles difference)
- No explicit communication needed — just observe cache state

---

## Comparison: Timing Attack vs Meltdown vs Spectre

||Timing Attack (OpenSSL)|Meltdown|Spectre|
|---|---|---|---|
|**Type**|Remote timing measurement|Transient execution + cache covert channel|Transient execution + branch prediction + cache|
|**Target**|RSA private key (q)|Kernel memory|Process memory (any)|
|**Condition**|Attacker sends queries to server|Run user-space code on victim machine|Run code on victim machine (including JS in browser)|
|**Leak mechanism**|Network timing statistics|Flush+Reload|Flush+Reload|
|**CPUs affected**|Software bug (OpenSSL)|Primarily Intel|Almost all CPUs|
|**Fix**|RSA Blinding|KPTI (>50% overhead)|No perfect fix|
|**Attacker model**|Outside adversary|Unprivileged user|Unprivileged user / JS in browser|

---

## Summary & Takeaways

- **Side-channel attack ≠ weak algorithm**: An implementation can leak secrets even if the mathematical algorithm is perfect. Cryptographic security must consider the physical implementation.
- **Timing is the most common and dangerous side channel**: Both local and remote timing attacks have been demonstrated in practice (Brumley & Boneh 2003).
- **Montgomery Reduction creates a timing leak** because the extra reduction step is input-dependent. Combined with OpenSSL using two multiplication routines → the attacker learns each bit of the RSA private key.
- **RSA Blinding is the best mitigation** — randomize input before decryption → timing no longer correlates with ciphertext.
- **Meltdown** exploits speculative execution across privilege boundaries: the CPU speculatively reads kernel memory before checking permissions → cache state is modified → Flush+Reload reads the data. Fix: KPTI (expensive in terms of performance).
- **Spectre** is harder: no privilege boundary crossing needed — just train the branch predictor so the victim process speculatively reads its own secret → leaks via cache. KPTI does not help.
- **Cache is a covert channel that cannot be completely eliminated** because shared cache is a fundamental optimization of modern CPUs. This is the fundamental tension between performance and security.
- ==**Security must be considered from the hardware design stage** — it's not just a software problem. Meltdown/Spectre showed that decades of CPU optimization without considering security implications have consequences.==

---

## Knowledge Links

- [[RSA Cryptosystem]]
- [[Cryptographic Hash Functions]]
- [[Memory Safety and Protection Mechanisms]]
- [[User Authentication]]
- [[Anonymity and Privacy]]
- [[Network Security]]
- [[Operating System Security]]
- [[Speculative Execution]]
- [[Cache Architecture]]
