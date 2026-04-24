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

## Tổng quan

**Side-channel attack** là lớp tấn công khai thác **thông tin rò rỉ từ quá trình thực thi** của hệ thống — chứ không phải từ điểm yếu trong thuật toán hay giao thức. Đây là điểm khiến chúng đặc biệt nguy hiểm: một hệ thống có thể được implement thuật toán mã hóa hoàn hảo về mặt toán học, nhưng cách thức chạy trên phần cứng thực tế lại rò rỉ secret key qua timing, power consumption, hay electromagnetic emissions. Bài giảng này phân tích hai case study quan trọng: **Timing Attack lên RSA/OpenSSL** (Brumley & Boneh, 2003) và hai lỗ hổng CPU lịch sử **Meltdown & Spectre** (2018).

---

## Nội dung chi tiết

### 1. Khái niệm Side Channel

#### 1.1 Định nghĩa

**Side channel** là kênh truyền thông tin **ngoài ý muốn** phát sinh từ quá trình thực thi vật lý của hệ thống máy tính:

- Timing information (thời gian thực thi)
- Power consumption (tiêu thụ điện năng)
- Electromagnetic emissions (bức xạ điện từ)
- Acoustic emanations (âm thanh)
- Cache behavior (hành vi cache)

**Side-channel attack**: tấn công dựa trên thông tin thu thập được từ các kênh này — không khai thác điểm yếu trong thuật toán, mà khai thác cách **implementation** của thuật toán đó.

> [!note] Covert Channel — khái niệm liên quan **Covert channel** là kênh truyền thông tin vốn **không được phép tồn tại** trong một hệ thống. Ví dụ: một process ở security level cao "rò rỉ" bí mật sang process security level thấp bằng cách thao túng mức độ sử dụng CPU hay cache — thứ mà process thứ hai có thể quan sát được.

#### 1.2 Mô hình tấn công

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

- **Passive attacker**: chỉ quan sát side channel (ví dụ: đo timing từ xa)
- **Active attacker**: vừa quan sát vừa **can thiệp/influence** hệ thống (ví dụ: gửi ciphertext để đo response time)

> [!question] Tại sao side-channel thường nhắm vào cryptographic constructions? Vì đây là nơi **secret data (private key, secret key)** được xử lý nhiều nhất và thường xuyên nhất. Nếu attacker học được private key, toàn bộ security của hệ thống sụp đổ. Hơn nữa, cryptographic operations thường có timing/power behavior phụ thuộc vào data — tạo điều kiện lý tưởng cho side-channel.

#### 1.3 Lịch sử: TEMPEST (từ 1943)

**TEMPEST** (Telecommunications Electronics Materials Protected from Emanating Spurious Transmissions) là chương trình nghiên cứu của NSA về electromagnetic emanations từ thiết bị điện tử. Phát hiện từ thời WWII: máy Bell 131B2 mixer (dùng XOR tín hiệu teleprinter với one-time tape) phát ra electromagnetic signal phản ánh plaintext — có thể bắt được từ xa.

Đây là bằng chứng lịch sử sớm nhất rằng side channel là vấn đề thực tế, không phải lý thuyết.

---

### 2. Các loại Side-Channel Attack phổ biến

#### 2.1 Power-Monitoring Attack

**Nguyên lý**: Mức tiêu thụ điện của phần cứng **phụ thuộc vào instruction đang thực thi** và data đang xử lý. Attacker đo dao động power consumption bằng oscilloscope.

**Simple Power Analysis (SPA)**: Quan sát một lần chạy duy nhất để phân biệt các operation khác nhau (ví dụ: bit 0 vs bit 1 trong RSA square-and-multiply).

**Setup thực tế**:

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

Graph power consumption thực tế theo clock cycle có thể trực tiếp lộ ra từng bit của secret key trong một số implementation ngây thơ.

> [!example] DPA — Differential Power Analysis Kỹ thuật nâng cao hơn SPA: đo **nhiều lần**, áp dụng phân tích thống kê để lọc noise và trích xuất thông tin về key, ngay cả khi single trace không đủ rõ ràng.

#### 2.2 Timing Attack

**Nguyên lý**: Thời gian thực thi của một operation phụ thuộc vào **giá trị của input/key** — attacker đo thời gian để suy luận thông tin bí mật.

**Hai loại:**

|Loại|Đặc điểm|Khó khăn|
|---|---|---|
|**Local timing attack**|Attacker trên cùng máy, đo chính xác|Dễ thực hiện hơn|
|**Remote timing attack**|Đo qua network|Phải loại bỏ network jitter: `exec_time = total_time − network_latency − other_noise`|

> [!note] Remote timing attack có khả thi không? Có — đã được chứng minh thực tế. Với đủ lượng mẫu và phân tích thống kê, timing signal yếu từ xa vẫn có thể được trích xuất. Paper của Brumley & Boneh (Usenix Security 2003) là minh chứng rõ ràng nhất.

---

### 3. Case Study: Timing Attack trên OpenSSL RSA

_(Dựa trên paper: "Remote Timing Attacks are Practical" — Brumley & Boneh, Usenix Security 2003)_

#### 3.1 Nền tảng: RSA Cryptosystem

**RSA** là public-key cryptosystem dựa trên bài toán phân tích nhân tử lớn.

**Key Generation:**

1. Chọn hai số nguyên tố lớn **p** và **q**
2. Tính `n = p × q` (modulus)
3. Tính `φ(n) = (p−1)(q−1)` (Euler's totient)
4. Chọn `e` coprime với `φ(n)` → **public key exponent**
5. Tính `d` sao cho `e·d ≡ 1 (mod φ(n))` → **private key exponent**

**Public key**: `(e, n)` | **Private key**: `(d, n)` _(hay `(d, p, q)` trong thực tế)_

**Encrypt/Decrypt:**

```
Encrypt:  c = mᵉ mod n
Decrypt:  m = cᵈ mod n
```

**Ví dụ toy:**

```
p=5, q=3 → n=15, φ(n)=8, e=3, d=3
Encrypt m=2: c = 2³ mod 15 = 8
Decrypt c=8: m = 8³ mod 15 = 512 mod 15 = 2 ✓
```

> [!note] OAEP Padding Trong thực tế, message M được pad trước khi encrypt bằng **Optimal Asymmetric Encryption Padding (OAEP)**: thêm known pattern + random number. Lý do: RSA thuần túy là **multiplicative** (c₁·c₂ = encrypt(m₁·m₂)) và **deterministic** (cùng m cho cùng c) — OAEP giải quyết cả hai vấn đề.

#### 3.2 OpenSSL RSA Implementation — Hai nguồn timing leak

**OpenSSL thực hiện RSA decryption bằng Chinese Remainder Theorem (CRT):**

```
mₚ = cᵈ mod p
m_q = cᵈ mod q
m = CRT(mₚ, m_q)
```

Tính `cᵈ mod q` cần **modular exponentiation** — đây là chỗ timing leak xảy ra.

---

**Nguồn 1: Montgomery Reduction — Extra Reduction**

**Montgomery Reduction** là thuật toán tính modular reduction hiệu quả hơn phép chia thông thường. Ý tưởng: chuyển về dạng reduction modulo _lũy thừa của 2_ (thực hiện bằng bit shift, rất nhanh).

**Montgomery Form:**

```
a  →  a' = aR mod q   (R là lũy thừa của 2)
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

**Timing leak**: bước `if z is odd: z = z + q` là **input-dependent** — xảy ra hay không phụ thuộc vào giá trị của input. Mỗi extra reduction tốn thêm thời gian.

**Phát hiện của Werner Schindler**: Xác suất xảy ra extra reduction trong khi tính `gᵈ mod q` tỷ lệ thuận với khoảng cách giữa g và q:

```
Pr[Extra Reduction] = (g mod q) / (2R)
```

Tức là: nếu g gần với q, số extra reductions nhiều hơn → thực thi **chậm hơn**. Đây là tín hiệu timing rõ ràng!

---

**Nguồn 2: Multiplication Routine — Karatsuba vs Normal**

OpenSSL có hai multiplication routine:

- **Karatsuba**: dùng khi hai số có **cùng số word** → `O(x^1.58)` (nhanh hơn)
- **Normal**: dùng khi hai số có **khác số word** → `O(xy) ≈ O(x²)` (chậm hơn)

Multiplication chiếm khoảng **40% tổng runtime** của RSA decryption → sự lựa chọn giữa hai routine tạo ra timing difference đáng kể.

---

**Hai nguồn timing counteract nhau:**

|Trường hợp|Montgomery Reduction|Multiplication Routine|Net Effect|
|---|---|---|---|
|`g < q`|Chậm hơn (nhiều extra reductions)|Nhanh hơn (Karatsuba)|Tổng hợp khó đoán|
|`g ≥ q`|Nhanh hơn (ít extra reductions)|Chậm hơn (Normal)|Tổng hợp khó đoán|

> [!note] Tại sao không triệt tiêu nhau hoàn toàn? Vì hai effect có **magnitude khác nhau** tùy theo giá trị cụ thể của g và các bits của q. Attacker khai thác chênh lệch còn sót lại (residual difference) qua thống kê.

#### 3.3 Attack Algorithm — Học từng bit của q

**Goal**: Học private key q, từng bit một.

**Approach**: Giả sử đã biết i−1 bits đầu của q. Để tìm bit thứ i:

1. Xây dựng `g` có cùng i−1 bits đầu với q, còn lại là 0
2. Xây dựng `ghi` giống g nhưng bit thứ i set = 1

**Suy luận:**

- Nếu bit thứ i của q là 1: `g < ghi < q`
- Nếu bit thứ i của q là 0: `g < q < ghi`

**Measurement:**

```
Construct: uₘ = gR⁻¹ mod n   (do cách OpenSSL xử lý Montgomery)
           u_hi = ghi·R⁻¹ mod n

Measure: t₁ = DecryptTime(uₘ)
         t₂ = DecryptTime(u_hi)
         Δ = |t₁ − t₂|
```

**Decision:**

- Nếu `g < q < ghi` → Δ lớn → bit của q là **0**
- Nếu cả g và ghi đều cùng phía so với q → Δ nhỏ → bit của q là **1**

**Statistical refinement** (để lọc noise):

- Lặp lại decryption nhiều lần để reduce variance
- Query một "neighborhood" của values xung quanh g và ghi thay vì chỉ một giá trị duy nhất

#### 3.4 Kết quả thực nghiệm

- Target: **OpenSSL 0.9.7**, máy 2.4GHz Pentium 4
- Attack hoạt động trong cả 3 scenario: same machine, 2 VMs, cross Ethernet LAN
- Graph (a): variance của decryption time **giảm dần** khi số lần sample tăng → signal converges
- Graph (b): "zero-one gap" (Δ khi bit=0 so với bit=1) tăng theo neighborhood size → thực tế ~500 queries/neighborhood là đủ

#### 3.5 Mitigations

|Biện pháp|Cách hoạt động|Hạn chế|
|---|---|---|
|**Dùng một multiplication routine duy nhất**|Loại bỏ một nguồn timing variance|Có thể chậm hơn|
|**Always do extra reduction**|Loại bỏ nguồn timing variance thứ hai|Overhead không đáng kể|
|**Quantize execution time**|Làm tròn thời gian → attacker không phân biệt được|Khó implement chính xác, vẫn có noise|
|**RSA Blinding** ✅|Trước decrypt: `x = r·eᵍ mod N` (r ngẫu nhiên); sau decrypt: `xᵈ/r mod N`|Thêm một phép tính nhỏ nhưng hiệu quả cao|

> [!tip] RSA Blinding là approach tốt nhất Bằng cách randomize ciphertext trước khi decrypt, timing của decryption không còn phụ thuộc vào giá trị ban đầu của ciphertext → attacker không thu thập được thông tin có ích dù đo timing bao nhiêu lần. Đây là **cryptographic countermeasure** đúng nghĩa, không phải "security through obscurity."

---

### 4. Case Study: Meltdown & Spectre (2018)

#### 4.1 Bối cảnh và Tầm quan trọng

Phát hiện giữa 2017 bởi Jann Horn (Google Project Zero) và nhiều nhóm độc lập khác; công bố tháng 1/2018. Được đánh giá là **một trong những lỗi nghiêm trọng nhất trong lịch sử máy tính**. Impact:

- Buộc redesign CPU, OS, compiler, browser JavaScript JIT engine, hypervisor
- Hệ thống đột ngột **chậm đi tới 50%** sau khi patch
- Ảnh hưởng đến hầu hết mọi CPU hiện đại

#### 4.2 Nền tảng: CPU Architecture Cần Thiết

Để hiểu Meltdown và Spectre, cần hiểu tại sao modern CPU lại dễ bị tấn công như vậy.

**CPU cơ bản**: Fetch → Decode → Execute cycle. Vấn đề: **memory access là bottleneck khổng lồ**.

**Latency của memory hierarchy** (trên CPU 3GHz, tức 0.3ns/cycle):

```
ALU/Registers  →  L0 cache → L1 cache → L2 cache → L3 cache → DRAM     → Storage
   ~1 cycle        ~1 cycle    ~4 cycles  ~10 cycles  ~40 cycles  200+ cycles  >>
```

Nếu CPU phải **stall** (dừng lại) mỗi lần đợi memory (200+ cycles), hiệu năng sẽ thảm họa. Vì vậy CPU hiện đại có nhiều optimization:

**1. Out-of-order Execution**: CPU không execute instructions theo thứ tự viết trong code, mà sắp xếp lại để tận dụng tối đa execution units trong khi đợi memory.

**2. Superscalar**: Nhiều execution units hoạt động song song.

**3. Branch Prediction**: Khi gặp `if` statement, CPU **đoán** nhánh nào sẽ đúng và bắt đầu execute trước khi biết kết quả thực sự. Nếu đoán đúng → tiết kiệm nhiều cycles. Nếu đoán sai → **rollback** về trạng thái trước (squash transient instructions).

**4. Virtual Memory & Privilege Levels (Protection Domains)**:

```
Virtual Address Space (32-bit Linux):
┌─────────────────┐  0xFFFFFFFF
│   Kernel space  │  ← chỉ kernel mới được access (ring 0)
├─────────────────┤  0xC0000000
│                 │
│   User space    │  ← user process (ring 3)
│                 │
└─────────────────┘  0x00000000
```

CPU dùng **page tables** (qua MMU) để map virtual address → physical address. TLB cache các mapping này. **Khi user process cố truy cập kernel memory** → CPU ném ra exception (page fault) → process bị terminate hoặc signal.

> [!note] Tại sao kernel được map vào address space của mọi process? Để **system calls** nhanh hơn: khi user process gọi system call, CPU chỉ cần switch privilege level (ring 3 → ring 0), không cần thay đổi page table hoàn toàn. Nếu kernel không được map vào user process space, mỗi system call phải thực hiện full page table switch — rất tốn kém. Đây chính là tradeoff dẫn đến Meltdown.

#### 4.3 Meltdown

**"Vulnerability basically melts security boundaries normally enforced by hardware."**

**Mục tiêu**: User-space process đọc được **toàn bộ kernel memory** — bao gồm passwords, keys, memory của process khác được kernel quản lý.

**Affected CPUs**: Chủ yếu Intel (speculative execution aggressively), một số ARM Cortex A-75, IBM Power.

---

**Cơ chế tấn công — Code ví dụ:**

```c
// Phiên bản naive (attacker nghĩ sẽ viết):
1.  s = a+b;
2.  t = s+c;
3.  u = t+d;
4.  v = u+e;
5.  if (v == 0) {
6.      w = kernel_mem[addr];   // ← FORBIDDEN: truy cập kernel memory
7.      x = w & 0x01;           // ← lấy 1 bit của byte kernel
8.      y = x * 4096;           // ← nhân để align theo page size
9.      z = user_mem[y];        // ← load vào cache dựa trên kernel data
10. }
```

**Vấn đề**: Dòng 5 (`if v == 0`) **luôn false** trong mọi trường hợp hợp lý → code trong if không bao giờ được execute → không đọc được gì.

---

**Exploit Meltdown — Transient Instructions:**

CPU với out-of-order execution thực hiện như sau:

```c
// CPU thực sự làm (parallel/out-of-order):
Sequential:              Speculative (transient):
1.  s = a+b;             w_ = kernel_mem[addr];  // CPU bắt đầu load sớm!
2.  t = s+c;             x_ = w_ & 0x01;         // speculatively execute
3.  u = t+d;             y_ = x_ * 4096;         // tính y_ từ kernel byte
4.  v = u+e;             z_ = user_mem[y_];       // ← LOAD VÀO CACHE!
5.  if (v == 0) {
6.                        w=w_; x=x_; y=y_; z=z_; // commit nếu branch đúng
7.  }
// Branch sai → rollback: registers về giá trị cũ → NHƯNG CACHE KHÔNG ĐƯỢC ROLLBACK!
```

CPU bắt đầu execute **speculatively** bên trong `if` block ngay khi branch condition đang được tính. Khi biết `v != 0` → rollback tất cả register changes. **Nhưng cache state KHÔNG bị rollback** — `user_mem[y_]` vẫn còn trong cache với `y_` phụ thuộc vào `kernel_mem[addr]`.

---

**Đọc kết quả qua Flush+Reload (Cache Covert Channel):**

```
Trước khi chạy transient code:
  → flush toàn bộ user_mem array ra khỏi cache (dùng clflush instruction)

Sau khi chạy:
  → reload từng phần tử user_mem[0], user_mem[4096], user_mem[8192], ...
  → đo reload time của từng phần tử

Kết quả:
  → user_mem[y_] reload nhanh hơn (còn trong cache!)
  → y_ = (kernel_byte & 0x01) * 4096
  → từ y_ suy ra kernel_byte ít nhất 1 bit
```

Lặp lại với các bitmask khác (`0x02`, `0x04`, ...) → đọc được toàn bộ byte kernel. Lặp lại với các địa chỉ khác → đọc được toàn bộ kernel memory.

> [!warning] Tại sao nhân với 4096? 4096 = page size. Nhân với 4096 đảm bảo các giá trị y khác nhau rơi vào **các cache line khác nhau** → có thể phân biệt bằng timing. Nếu nhân với 1 thì nhiều giá trị y cùng vào một cache line → không phân biệt được.

**Xử lý exceptions:**

CPU ném exception khi speculatively load kernel memory. Attacker phải suppress exception để code tiếp tục chạy:

- **Exception handling**: dùng `signal` handler để catch page fault và continue
- **Exception suppression**: dùng hardware transactional memory (TSX) để suppress exception trong transaction

#### 4.4 Meltdown Mitigation — KPTI

**Kernel Page Table Isolation (KPTI)** — trước đó gọi là **KAISER** (Kernel Address Isolation to have Side-channels Efficiently Removed):

**Ý tưởng**: Tách page table thành hai bộ hoàn toàn:

```
Before KPTI:                    After KPTI:
User mode page table:           User mode page table:
┌─────────────────┐             ┌─────────────────┐
│  Kernel space   │ ← MAPPED    │  Kernel: minimal│ ← chỉ stub để switch
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

**Pros**: Giải quyết root cause — user process không còn map kernel pages → không thể speculatively access kernel memory.

**Cons**: Mỗi **system call** hay **interrupt** phải switch page table và **flush TLB** → performance hit lên đến **>50%** cho workloads nhiều system call (database, I/O-bound).

> [!note] Intel Hardware Mitigations Intel sau đó thêm hardware/firmware mitigations ở các CPU thế hệ mới hơn giúp giảm performance impact của KPTI. Các CPU ARM và AMD ít bị ảnh hưởng bởi Meltdown hơn do có design speculative execution khác nhau.

---

#### 4.5 Spectre (Variant 1: Bounds Check Bypassing)

Spectre **khác Meltdown** về bản chất:

- Meltdown: user-space đọc **kernel** memory của chính nó (cross privilege boundary)
- Spectre: attacker đánh lừa **chính victim process** đọc memory của mình rồi leak ra ngoài (cross process boundary hay trong cùng process)

**Spectre ảnh hưởng hầu hết CPU** (không chỉ Intel) và **KPTI không giúp được gì**.

---

**Concept: Bounds Check Bypassing**

Code victim trông hoàn toàn đúng:

```c
if (x < array1_size)
    y = array2[array1[x] * 4096];
```

- `x` là biến do **attacker control**
- Bounds check (`x < array1_size`) trông có vẻ an toàn
- Nhưng CPU có **branch predictor**...

---

**3 bước tấn công Spectre Variant 1:**

**Bước 1: Train branch predictor**

Attacker gọi đoạn code nhiều lần với `x < array1_size` (in-bounds) → Branch predictor học: "nhánh true xảy ra thường xuyên" → sẽ predict TRUE tiếp theo.

**Bước 2: Supply out-of-bounds x**

Attacker gửi `x` có giá trị **vượt ngoài array1_size**, trỏ đến vùng secret memory trong process:

```c
x = (addr_of_secret - base_of_array1)  // out-of-bounds, nhưng nằm trong process memory
```

CPU speculatively execute (vì branch predictor dự đoán `true`):

```c
// Speculatively:
y = array2[array1[x] * 4096];  // array1[x] = secret byte!
                                 // array2[secret * 4096] được load vào cache
```

Khi CPU nhận ra bounds check fail → rollback. Nhưng cache đã bị modify!

**Bước 3: Read cache state**

Attacker dùng **Flush+Reload** tương tự Meltdown để đọc giá trị nào của `array2` đang trong cache → suy ra `secret byte`.

> [!warning] Sự khác biệt quan trọng với Meltdown Meltdown đọc memory **không được phép** (kernel space). Spectre đánh lừa victim đọc memory **được phép truy cập bởi victim** (nằm trong address space của victim) — nhưng attacker không trực tiếp có permission đó. Đây là lý do Spectre khó mitigate hơn nhiều.

**Attack vectors thực tế:**

- **Browser JavaScript**: Microsoft PoC đọc data từ tab khác hoặc browser data của chính nó — tất cả qua JavaScript chạy trong browser JIT!
- **Linux kernel eBPF**: Google PoC nhắm vào Linux kernel packet filter

#### 4.6 Spectre Variant 1 Mitigations

|Biện pháp|Cơ chế|Trade-off|
|---|---|---|
|**Serializing instruction (lfence)**|Đặt `lfence` trước bounds check → ngừng speculative execution|Performance hit đáng kể; cần instrument toàn bộ code|
|**Chrome: site isolation**|Mỗi website trong một process riêng → cross-site Spectre không đọc được cross-process memory|Tốn RAM hơn|
|**WebKit: index masking**|Thay bounds check bằng bitwise AND với mask → không có branch để predict|Thay đổi semantics phức tạp|
|**Giảm độ phân giải JavaScript timers**|Không cho attacker đo timing chính xác → không thể thực hiện Flush+Reload|Ảnh hưởng đến timing-dependent web apps|

> [!question] Tại sao Spectre khó fix hơn Meltdown? Meltdown là lỗi của một implementation cụ thể (Intel aggressive speculative execution across privilege boundary). KPTI là một kernel-level fix rõ ràng. Spectre là lỗi **fundamental** trong design của branch prediction: cần speculation để nhanh, nhưng speculation tạo covert channel qua cache. Mọi fix đều có trade-off hiệu năng, và không có giải pháp hoàn hảo nào không đổi performance.

---

### 5. Cache làm Covert Channel — Flush+Reload

Cả Meltdown và Spectre đều dùng **cache làm covert channel** để exfiltrate data. Đây là kỹ thuật **Flush+Reload**:

```
SENDER (transient/speculative code muốn truyền secret bit):
  → Load array[secret * 4096] vào cache

RECEIVER (attacker code):
1. Flush: dùng clflush để xóa array[] ra khỏi cache
2. Trigger sender
3. Reload: thử load array[0], array[4096], array[8192], ...
4. Đo thời gian từng load:
   - Cache hit (~4 cycles) → đây là index được sender load → đây là secret!
   - Cache miss (~200 cycles) → không phải
```

**Tại sao cache là covert channel tốt?**

- Cache **shared** giữa processes (và giữa user/kernel trong cùng core)
- Timing difference giữa cache hit/miss rất lớn và đo được (~196 cycles difference)
- Không cần explicit communication — chỉ cần observe cache state

---

## So sánh: Timing Attack vs Meltdown vs Spectre

||Timing Attack (OpenSSL)|Meltdown|Spectre|
|---|---|---|---|
|**Loại**|Remote timing measurement|Transient execution + cache covert channel|Transient execution + branch prediction + cache|
|**Target**|RSA private key (q)|Kernel memory|Process memory (bất kỳ)|
|**Điều kiện**|Attacker gửi queries đến server|Chạy user-space code trên victim machine|Chạy code trên victim machine (kể cả JS trong browser)|
|**Cơ chế leak**|Network timing statistics|Flush+Reload|Flush+Reload|
|**CPUs affected**|Software bug (OpenSSL)|Chủ yếu Intel|Hầu hết mọi CPU|
|**Fix**|RSA Blinding|KPTI (>50% overhead)|Không có fix hoàn hảo|
|**Attacker model**|Outside adversary|Unprivileged user|Unprivileged user / JS in browser|

---

## Tóm tắt & Takeaways

- **Side-channel attack ≠ thuật toán yếu**: Implementation có thể leak secret dù thuật toán toán học hoàn hảo. Cryptographic security phải xét đến physical implementation.
- **Timing là side channel phổ biến và nguy hiểm nhất**: Cả local lẫn remote timing attack đều đã được chứng minh trong thực tế (Brumley & Boneh 2003).
- **Montgomery Reduction tạo timing leak** vì extra reduction step phụ thuộc input. Cộng với việc OpenSSL dùng hai multiplication routines → attacker học từng bit của RSA private key.
- **RSA Blinding là mitigation tốt nhất** — randomize input trước khi decrypt → timing không còn tương quan với ciphertext.
- **Meltdown** khai thác speculative execution vượt qua privilege boundary: CPU speculatively đọc kernel memory trước khi kiểm tra permission → cache state bị modify → Flush+Reload đọc data. Fix: KPTI (đắt về performance).
- **Spectre** khó hơn: không cần vượt privilege boundary — chỉ cần train branch predictor để victim process tự speculatively đọc secret của mình → leak qua cache. KPTI không giúp được.
- **Cache là covert channel không thể loại bỏ hoàn toàn** vì shared cache là optimization cơ bản của modern CPU. Đây là fundamental tension giữa performance và security.
- ==**Security phải được xem xét từ lúc thiết kế hardware** — không chỉ là vấn đề của software. Meltdown/Spectre cho thấy hàng thập kỷ CPU optimization mà không tính đến security implications.==

---

## Liên kết kiến thức

- [[RSA Cryptosystem]]
- [[Cryptographic Hash Functions]]
- [[Memory Safety and Protection Mechanisms]]
- [[User Authentication]]
- [[Anonymity and Privacy]]
- [[Network Security]]
- [[Operating System Security]]
- [[Speculative Execution]]
- [[Cache Architecture]]