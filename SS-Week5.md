---

tags:

- security
- authentication
- user-authentication
- password
- cryptography

---

# User Authentication

## Tổng quan

**User Authentication** (xác thực người dùng) là một trong những thành phần nền tảng của bảo mật hệ thống. Đây là quá trình xác nhận danh tính của một thực thể (người dùng, thiết bị, hoặc hệ thống) trước khi cho phép truy cập tài nguyên. Tuy nghe có vẻ đơn giản, authentication thực tế rất khó thực hiện an toàn vì nó liên quan đến nhiều điểm yếu tiềm tàng: từ cách lưu trữ mật khẩu, cách người dùng chọn mật khẩu, đến cơ chế khôi phục tài khoản.

---

## Nội dung chi tiết

### 1. Authentication vs Authorization

Hai khái niệm này thường bị nhầm lẫn nhau nhưng hoàn toàn khác biệt:

|Khái niệm|Định nghĩa|Câu hỏi trả lời|
|---|---|---|
|**Authentication (AuthN)**|Xác nhận danh tính — _bạn là ai?_|"Are you who you claim to be?"|
|**Authorization (AuthZ)**|Phân quyền truy cập — _bạn được làm gì?_|"What are you allowed to do?"|

> [!question] Câu hỏi thảo luận **OAuth** là cơ chế cho AuthN hay AuthZ?
> 
> → OAuth 2.0 về bản chất là **Authorization** framework (ủy quyền truy cập tài nguyên). OpenID Connect (xây dựng trên OAuth 2.0) mới là cơ chế **Authentication**.

---

### 2. Các phương thức Authentication

Authentication có thể dựa trên ba yếu tố (factors):

- **Something you know** (kiến thức): passwords, PIN, passphrase
- **Something you have** (sở hữu): smart card, OTP token, điện thoại
- **Something you are** (bản thân): biometric — vân tay, khuôn mặt, mống mắt

> [!note] Tại sao secure authentication lại khó? Mỗi yếu tố đều có điểm yếu riêng: password có thể bị đoán/đánh cắp, token vật lý có thể mất, biometric có thể bị giả mạo. Kết hợp nhiều yếu tố (Multi-Factor Authentication) là hướng đi đúng nhưng phức tạp hơn về triển khai và usability.

---

### 3. Passwords — Nền tảng của Authentication

Mặc dù liên tục bị "dự đoán sẽ lỗi thời" qua từng năm, password vẫn là cơ chế xác thực phổ biến nhất vì:

- Dễ triển khai phía server
- Dễ tùy chỉnh (có thể đổi, đặt lại)
- Người dùng đã quen thuộc

**Vòng đời của một password** gồm ba giai đoạn:

1. **Bootstrapping**: Người dùng đăng ký tài khoản, cung cấp username + password (+ email, câu hỏi bảo mật, 2FA…)
2. **Authentication**: Mỗi lần đăng nhập, server kiểm tra cặp (username, password)
3. **Recovery**: Khi quên mật khẩu → **đây là điểm yếu nguy hiểm nhất**

> [!warning] Nguyên tắc bảo mật tổng thể `security = min(password_security, recovery_security)`
> 
> Một hệ thống có password phức tạp nhưng recovery dễ (ví dụ: câu hỏi bảo mật đơn giản) vẫn là hệ thống yếu. Bảo mật bằng mức thấp nhất trong chuỗi.

---

### 4. Password Storage — Các phương án và điểm yếu

#### 4.1 Strawman #1: Lưu cleartext ❌

```
username : password
```

- **Vấn đề**: Nếu database bị đánh cắp (malicious admin, SQL injection…), toàn bộ mật khẩu lộ ngay lập tức.
- **Ví dụ lịch sử**: File `/etc/passwd` trong các hệ thống Unix cũ.

#### 4.2 Strawman #2: Lưu hash ⚠️

```
username : H(password)
```

- Khi đăng nhập, server hash mật khẩu gửi đến và so sánh với hash đã lưu.
- **Cải tiến**: Attacker đánh cắp database chỉ thấy hash, không thấy mật khẩu gốc.
- **Vẫn dễ bị tấn công**: Dictionary Attack.

#### 4.3 Dictionary Attack

Kẻ tấn công thực hiện:

1. Đánh cắp database chứa `username : H(password)`
2. Chuẩn bị danh sách mật khẩu phổ biến (English dictionary, common passwords…)
3. Tính `H(word)` cho từng từ
4. So sánh với các hash trong database

**Vấn đề**: Dictionary hiệu quả rất lớn, nhưng attacker chỉ cần tính một lần và dùng lại mãi. Đây là **offline attack** — không cần tương tác với server.

---

### 5. Password Hashing Algorithm — Dùng gì?

> [!warning] Không dùng MD5, SHA-256 để hash password! MD5 và SHA-256 được thiết kế để **nhanh** — điều đó có lợi cho attacker vì họ có thể thử hàng tỷ passwords/giây.

Cần dùng **Key Derivation Function (KDF)** với **work factor** có thể cấu hình (yêu cầu CPU/RAM cao hơn):

|Algorithm|Đặc điểm|Ghi chú|
|---|---|---|
|**PBKDF2**|NIST approved, FIPS-140 validated|Không memory-hard → ASIC/GPU có thể tăng tốc|
|**bcrypt**|Work factor cấu hình được|Không memory-hard|
|**scrypt**|Memory-hard|ASIC-resistant|
|**Argon2**|Memory-hard, GPU-resistant|✅ **Winner of 2015 Password Hashing Competition** — khuyên dùng|

> [!tip] Tại sao memory-hard lại quan trọng? ASIC và GPU có thể thực hiện tính toán song song với tốc độ rất cao. Nếu algorithm yêu cầu nhiều RAM, attacker không thể chạy nhiều instance song song → giảm tốc độ brute-force xuống đáng kể.

---

### 6. Rainbow Tables — Space-Time Tradeoff

#### Ý tưởng cốt lõi

Dictionary attack thông thường yêu cầu tính toán lại hash mỗi lần (tốn CPU). Rainbow table giải quyết bằng cách **precompute và lưu trữ** — đánh đổi storage lấy tốc độ crack.

**Nguyên lý**:

- **Hash function H**: password → hash (không thể đảo ngược)
- **Reduction function R**: hash → password (giảm hash về dạng password hợp lệ — không phải inverse của H!)

#### Tạo Rainbow Table

```
p₀ → H(p₀) → R(H(p₀)) → H(R(H(p₀))) → ... → pₙ
```

Chỉ lưu: **(p₀, pₙ)** — startpoint và endpoint của mỗi chain.

#### Crack một hash h

```
R(h) → H(R(h)) → R(H(R(h))) → ...
```

Sau mỗi bước R(), kiểm tra xem output có phải endpoint trong table không. Nếu có → tái tạo chain từ startpoint tương ứng để tìm preimage của h.

> [!example] Ví dụ trong slide (in-class activity)
> 
> - Startpoints: 32, 14, 11, 20
> - Chain length: 4 bước
> - R(x) = 5×x; H(x) = x mod 13
> - Tìm preimage của hash = 9

---

### 7. Salted Passwords — Giải pháp chống Rainbow Table

**Vấn đề của hash thuần túy**: Một giá trị hash có thể so sánh với nhiều precomputed value cùng lúc.

**Giải pháp: Salt**

```
username : salt, H(salt ∥ password)
```

- **Salt** là giá trị ngẫu nhiên, unique per user, lưu công khai cùng hash
- Hai user có cùng password → hai hash khác nhau (vì salt khác nhau)
- Pre-computed rainbow table trở nên **vô dụng** vì attacker phải recompute riêng cho mỗi salt

> [!note] Salt không phải bí mật Salt được lưu cleartext cùng hash. Giá trị của nó không phải là bí mật — nó chỉ đảm bảo mỗi user có "không gian hash" riêng, buộc attacker phải tấn công từng user riêng lẻ.

---

### 8. Password Breach Detection — HoneyWords

#### Vấn đề

Ngay cả với salted hash, nếu database bị đánh cắp và một số password bị crack, attacker sẽ dùng chúng để đăng nhập. Làm sao phát hiện điều này?

#### Giải pháp: HoneyWords (Analogy với HoneyPot)

**Cơ chế**:

- Mỗi user có: 1 real password + nhiều **decoy passwords** (honeywords)
- Tất cả đều được lưu dưới dạng salted hash — không phân biệt được real hay decoy
- **HoneyChecker**: module isolated, bảo mật cao, biết index của real password

**Luồng authentication**:

1. User gửi password đến server
2. Server kiểm tra password có trong danh sách (real + decoy) không
3. Nếu có → hỏi HoneyChecker: "Index này có phải real password không?"
4. HoneyChecker trả về YES/NO
5. Nếu NO → **alarm!** → block account (database có thể đã bị compromise)

> [!tip] Điều kiện để HoneyWords hiệu quả Decoy passwords phải **không thể phân biệt** với real password (cùng entropy, format, pattern). Nếu honeywords trông yếu hơn real password, attacker có thể đoán cái nào là real.
> 
> 📖 Further reading: _The Impact of Exposed Passwords on Honeyword Efficacy_ (Usenix Security 2024)

---

### 9. Password Selection — Passwords tốt và xấu

#### Passwords yếu (nên tránh)

- **Default passwords**: `password`, `admin`, `guest`, `default`
- **Dictionary words**: `chameleon`, `RedSox`
- **Words + numbers**: `password1`, `john1234`
- **Leet speak obfuscation**: `p@ssw0rd`, `l33th4x0r` — attacker biết trick này!
- **Doubled words**: `crabcrab`, `passpass`
- **Keyboard sequences**: `qwerty`, `12345`, `asdfgh`
- **Numeric sequences**: `314159` (pi), `911`
- **Personal info**: ngày sinh, số điện thoại, biển số xe

#### Passwords tốt (high-entropy)

```
vJI6xft.CNqG295Fvu9B3w/5cY   ← Rất tốt nhưng không thể nhớ
```

**Kỹ thuật thực tế để tạo memorable high-entropy passwords**:

1. **Sentence to password**: Lấy chữ cái đầu của một câu:
    
    - `I really like the "51.502: Systems Security" course!`  
        → `Irlt"51.502:SS"c!`
2. **Passphrase** (random words):
    
    - `CorrectHorseBatteryStaple` — được xkcd popularize, entropy cao
3. **Random words + tweaks**:
    
    - `--31_throw_SIGNAL_march_74--` — khó đoán, dễ nhớ hơn random chars

---

### 10. Password Policies

Chính sách mật khẩu của tổ chức thường gồm:

- **Format restriction**: độ dài tối thiểu, bắt buộc chữ hoa/thường/số/ký tự đặc biệt
- **Forbidden words**: chặn từ điển, mật khẩu phổ biến, formats như ngày tháng/số điện thoại
- **Blacklist**: kể cả mật khẩu "tốt" nếu đã bị lộ trong các breach trước
- **Expiration**: bắt đổi mật khẩu định kỳ (mỗi X ngày), không được dùng lại mật khẩu cũ

> [!warning] Tranh cãi về password expiration Nhiều nghiên cứu gần đây cho thấy forced expiration thực ra có hại: người dùng chọn mật khẩu yếu hơn và dễ đoán hơn (ví dụ: `Password1!` → `Password2!`). NIST SP 800-63B hiện **không khuyến nghị** forced expiration định kỳ, trừ khi có bằng chứng compromise.

---

### 11. One-Time Password (OTP)

OTP giải quyết vấn đề **password bị nghe lén** — mỗi lần đăng nhập dùng mật khẩu khác nhau.

#### 11.1 Lamport's OTP (Hash Chain)

**Setup**:

```
Alice tính: s → H(s) → H²(s) → H³(s) → ... → H¹⁰⁰⁰(s)
Alice gửi H¹⁰⁰⁰(s) cho server (bootstrap)
```

**Authentication**:

- Session 1: Alice gửi H⁹⁹⁹(s) → Server verify: `H(H⁹⁹⁹(s)) == H¹⁰⁰⁰(s)` ✓
- Session 2: Alice gửi H⁹⁹⁸(s) → Server verify: `H(H⁹⁹⁸(s)) == H⁹⁹⁹(s)` ✓
- ...

**Tính chất**: OTP đã dùng không thể dùng lại vì attacker phải đảo ngược hash function.

#### 11.2 Time-based OTP (TOTP)

```
Alice bootstraps server với K (shared secret)
Mỗi lần authenticate: Alice gửi H(K, T) — T là timestamp hiện tại
```

- Server biết K và T → verify độc lập
- **Dùng trong**: Google Authenticator, các app 2FA

#### 11.3 Counter-based OTP (HOTP)

```
Alice và server chia sẻ K và counter C (bắt đầu từ 0)
Mỗi session: Alice gửi H(K, C++) — C tăng lên sau mỗi lần dùng
```

#### 11.4 Challenge-Response OTP (Nonce-based)

```
Alice bootstraps server với K
Mỗi session: Server gửi Nonce ngẫu nhiên
Alice gửi H(K, Nonce)
```

- Server verify: tính lại H(K, Nonce) và so sánh
- **Ưu điểm**: Không cần đồng bộ thời gian, không cần counter

---

### 12. Two-Factor Authentication (2FA)

**Vấn đề của single-factor**: Nếu password bị đánh cắp (phishing, breach…), attacker có thể đăng nhập.

**Giải pháp**: Kết hợp 2 factors:

- **Passwords** (something you know) + **OTP** (something you have)

**Triển khai thực tế**:

- **Physical tokens**: thiết bị tạo OTP
- **Apps**: Google Authenticator, Authy (TOTP)
- **Universal 2nd Factor (U2F)**: USB hoặc NFC token (YubiKey…)
- **Password + Device**: Xác nhận qua điện thoại đã đăng ký

> [!note] Usability trade-off 2FA tăng bảo mật đáng kể nhưng có thể gây khó chịu nếu yêu cầu mọi lần đăng nhập. Nhiều hệ thống áp dụng risk-based authentication: chỉ yêu cầu 2FA khi phát hiện đăng nhập từ thiết bị/địa điểm lạ.

---

### 13. Các phương thức Authentication thay thế

#### Đánh giá theo ba tiêu chí

|Tiêu chí|Mô tả|
|---|---|
|**Usability**|Dễ học, ít lỗi, dễ khôi phục khi mất|
|**Deployability**|Chi phí server, browser support, cost|
|**Security**|Chống observation, chống phishing, chống theft|

#### Certificates (Client Certificate Authentication)

- **Ưu**: Bảo mật cao, không cần nhớ password
- **Nhược**: Khó quản lý cho người dùng thông thường, deployability thấp

#### Biometrics (Sinh trắc học)

- Vân tay, khuôn mặt, mống mắt, giọng nói
- **Ưu**: Unique, luôn "mang theo", tiện lợi
- **Nhược**:
    - Không thể thay đổi nếu bị compromise (không thể "đổi vân tay")
    - Privacy concerns
    - False acceptance/rejection rates
    - Có thể bị giả mạo (deepfake, vân tay giả)

---

### 14. OAuth 2.0 và OpenID Connect

> [!note] Tài liệu học thêm
> 
> - **An Illustrated Guide to OAuth and OpenID Connect** (16:35): https://youtu.be/t18YB3xDfXI
> - **OAuth 2.0 and OpenID Connect (in plain English)** (~1hr): https://youtu.be/996OiexHze0

**OAuth 2.0** là **Authorization** framework cho phép ứng dụng thứ ba truy cập tài nguyên thay mặt người dùng mà không cần biết mật khẩu.

**OpenID Connect (OIDC)** là lớp **Authentication** xây dựng trên OAuth 2.0 — cung cấp ID Token xác nhận danh tính người dùng.

---

## Ví dụ minh họa

### In-class Activity: Mini Rainbow Table

**Tham số**:

- Startpoints: 32, 14, 11, 20
- Chain length: 4 (H và R dùng 3 lần mỗi cái)
- R(x) = 5×x; H(x) = x mod 13

**Chain từ startpoint 32**:

```
32 → H(32) = 32 mod 13 = 6 → R(6) = 30 → H(30) = 30 mod 13 = 4 → R(4) = 20 (endpoint)
```

**Crack hash h = 9**:

1. R(9) = 45 → check endpoint? No
2. H(45) = 45 mod 13 = 6 → R(6) = 30 → check? No
3. H(30) = 4 → R(4) = 20 → **20 là endpoint!** → tìm chain có endpoint 20 → tái tạo chain → tìm preimage

---

## So sánh Password Hashing Algorithms

|Algorithm|Memory-hard|ASIC-resistant|GPU-resistant|Chuẩn hóa|
|---|---|---|---|---|
|MD5/SHA-256|❌|❌|❌|Không dùng cho password|
|PBKDF2|❌|❌|❌|NIST/FIPS-140|
|bcrypt|❌|Một phần|Một phần|Widely used|
|scrypt|✅|✅|Một phần|—|
|**Argon2**|✅|✅|✅|**Khuyến nghị**|

---

## Tóm tắt & Takeaways

- **Authentication ≠ Authorization**: AuthN xác nhận danh tính, AuthZ phân quyền. OAuth là AuthZ, OpenID Connect là AuthN.
- **Bảo mật tổng thể = mức thấp nhất**: `security = min(password_security, recovery_security)` — recovery yếu thì toàn bộ hệ thống yếu.
- **Không bao giờ lưu password cleartext**; không dùng MD5/SHA-256 để hash password — dùng **Argon2** hoặc bcrypt với work factor cao.
- **Salt** phá vỡ rainbow table bằng cách buộc attacker phải tấn công từng user riêng lẻ.
- **HoneyWords** là cơ chế phát hiện breach thông minh — trigger alarm khi decoy password được dùng.
- **OTP** giải quyết vấn đề password bị nghe lén; **2FA** bảo vệ ngay cả khi password bị đánh cắp.
- Không có giải pháp authentication hoàn hảo — luôn có trade-off giữa **Usability**, **Deployability**, và **Security**.

---

## Liên kết kiến thức

- [[Cryptographic Hash Functions]]
- [[Key Derivation Functions]]
- [[Multi-Factor Authentication]]
- [[OAuth 2.0]]
- [[OpenID Connect]]
- [[HoneyPot Systems]]
- [[Rainbow Tables]]
- [[Network Security]]
- [[SS-Week4]]