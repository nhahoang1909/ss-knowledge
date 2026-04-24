---

tags:

- security
- authentication
- user-authentication
- password
- cryptography

---

# User Authentication

## Overview

**User Authentication** is one of the foundational components of system security. It is the process of verifying the identity of an entity (user, device, or system) before granting access to resources. Although it sounds straightforward, authentication is very difficult to implement securely because it involves many potential weaknesses: from how passwords are stored, how users choose passwords, to account recovery mechanisms.

---

## Detailed Content

### 1. Authentication vs Authorization

These two concepts are often confused but are fundamentally different:

|Concept|Definition|Question Answered|
|---|---|---|
|**Authentication (AuthN)**|Verify identity — _who are you?_|"Are you who you claim to be?"|
|**Authorization (AuthZ)**|Access control — _what can you do?_|"What are you allowed to do?"|

> [!question] Discussion Question Is **OAuth** a mechanism for AuthN or AuthZ?
> 
> → OAuth 2.0 is fundamentally an **Authorization** framework (delegating resource access). OpenID Connect (built on top of OAuth 2.0) is the **Authentication** mechanism.

---

### 2. Authentication Methods

Authentication can be based on three factors:

- **Something you know** (knowledge): passwords, PIN, passphrase
- **Something you have** (possession): smart card, OTP token, phone
- **Something you are** (inherence): biometrics — fingerprint, face, iris

> [!note] Why is secure authentication difficult? Each factor has its own weaknesses: passwords can be guessed/stolen, physical tokens can be lost, biometrics can be spoofed. Combining multiple factors (Multi-Factor Authentication) is the right approach but more complex to implement and impacts usability.

---

### 3. Passwords — The Foundation of Authentication

Despite being continuously "predicted to become obsolete" year after year, passwords remain the most common authentication mechanism because:

- Easy to implement server-side
- Easy to customize (can be changed, reset)
- Users are already familiar with them

**The lifecycle of a password** consists of three phases:

1. **Bootstrapping**: User registers an account, providing username + password (+ email, security questions, 2FA…)
2. **Authentication**: Each login, the server checks the (username, password) pair
3. **Recovery**: When the password is forgotten → **this is the most dangerous weakness**

> [!warning] Overall Security Principle `security = min(password_security, recovery_security)`
> 
> A system with complex passwords but easy recovery (e.g., simple security questions) is still a weak system. Security equals the weakest link in the chain.

---

### 4. Password Storage — Approaches and Weaknesses

#### 4.1 Strawman #1: Storing in Cleartext ❌

```
username : password
```

- **Problem**: If the database is stolen (malicious admin, SQL injection…), all passwords are immediately exposed.
- **Historical example**: The `/etc/passwd` file in legacy Unix systems.

#### 4.2 Strawman #2: Storing Hashes ⚠️

```
username : H(password)
```

- During login, the server hashes the submitted password and compares it with the stored hash.
- **Improvement**: An attacker who steals the database only sees hashes, not original passwords.
- **Still vulnerable**: Dictionary Attack.

#### 4.3 Dictionary Attack

An attacker performs:

1. Steal the database containing `username : H(password)`
2. Prepare a list of common passwords (English dictionary, common passwords…)
3. Compute `H(word)` for each word
4. Compare against hashes in the database

**Problem**: The dictionary is very effective, and the attacker only needs to compute it once and reuse it forever. This is an **offline attack** — no interaction with the server is needed.

---

### 5. Password Hashing Algorithm — What to Use?

> [!warning] Do not use MD5 or SHA-256 to hash passwords! MD5 and SHA-256 are designed to be **fast** — which benefits attackers since they can try billions of passwords per second.

Use a **Key Derivation Function (KDF)** with a configurable **work factor** (requiring more CPU/RAM):

|Algorithm|Characteristics|Notes|
|---|---|---|
|**PBKDF2**|NIST approved, FIPS-140 validated|Not memory-hard → ASIC/GPU can speed it up|
|**bcrypt**|Configurable work factor|Not memory-hard|
|**scrypt**|Memory-hard|ASIC-resistant|
|**Argon2**|Memory-hard, GPU-resistant|✅ **Winner of the 2015 Password Hashing Competition** — recommended|

> [!tip] Why is memory-hardness important? ASICs and GPUs can perform parallel computations at very high speeds. If the algorithm requires a lot of RAM, the attacker cannot run many instances in parallel → significantly reducing brute-force speed.

---

### 6. Rainbow Tables — Space-Time Tradeoff

#### Core Idea

A regular dictionary attack requires recomputing hashes each time (CPU-intensive). Rainbow tables solve this by **precomputing and storing** — trading storage for cracking speed.

**Principle**:

- **Hash function H**: password → hash (irreversible)
- **Reduction function R**: hash → password (reduces hash to a valid password format — not the inverse of H!)

#### Building a Rainbow Table

```
p₀ → H(p₀) → R(H(p₀)) → H(R(H(p₀))) → ... → pₙ
```

Only store: **(p₀, pₙ)** — the startpoint and endpoint of each chain.

#### Cracking a Hash h

```
R(h) → H(R(h)) → R(H(R(h))) → ...
```

After each R() step, check if the output is an endpoint in the table. If so → reconstruct the chain from the corresponding startpoint to find the preimage of h.

> [!example] Example from the Slides (In-class Activity)
> 
> - Startpoints: 32, 14, 11, 20
> - Chain length: 4 steps
> - R(x) = 5×x; H(x) = x mod 13
> - Find the preimage of hash = 9

---

### 7. Salted Passwords — The Solution Against Rainbow Tables

**Problem with plain hashing**: A single hash value can be compared against many precomputed values simultaneously.

**Solution: Salt**

```
username : salt, H(salt ∥ password)
```

- **Salt** is a random value, unique per user, stored in plaintext alongside the hash
- Two users with the same password → two different hashes (because the salts differ)
- Precomputed rainbow tables become **useless** because the attacker must recompute separately for each salt

> [!note] Salt is not a secret Salt is stored in cleartext alongside the hash. Its value is not meant to be secret — it simply ensures each user has their own "hash space," forcing the attacker to attack each user individually.

---

### 8. Password Breach Detection — HoneyWords

#### Problem

Even with salted hashes, if the database is stolen and some passwords are cracked, the attacker will use them to log in. How do we detect this?

#### Solution: HoneyWords (Analogy with HoneyPot)

**Mechanism**:

- Each user has: 1 real password + multiple **decoy passwords** (honeywords)
- All are stored as salted hashes — indistinguishable between real and decoy
- **HoneyChecker**: an isolated, highly secure module that knows the index of the real password

**Authentication flow**:

1. User sends password to the server
2. Server checks if the password is in the list (real + decoy)
3. If yes → ask HoneyChecker: "Is this index the real password?"
4. HoneyChecker returns YES/NO
5. If NO → **alarm!** → block account (the database may have been compromised)

> [!tip] Requirements for HoneyWords to Be Effective Decoy passwords must be **indistinguishable** from the real password (same entropy, format, pattern). If honeywords look weaker than the real password, the attacker can guess which one is real.
> 
> 📖 Further reading: _The Impact of Exposed Passwords on Honeyword Efficacy_ (Usenix Security 2024)

---

### 9. Password Selection — Good and Bad Passwords

#### Weak Passwords (Avoid These)

- **Default passwords**: `password`, `admin`, `guest`, `default`
- **Dictionary words**: `chameleon`, `RedSox`
- **Words + numbers**: `password1`, `john1234`
- **Leet speak obfuscation**: `p@ssw0rd`, `l33th4x0r` — attackers know this trick!
- **Doubled words**: `crabcrab`, `passpass`
- **Keyboard sequences**: `qwerty`, `12345`, `asdfgh`
- **Numeric sequences**: `314159` (pi), `911`
- **Personal info**: date of birth, phone number, license plate

#### Strong Passwords (High-entropy)

```
vJI6xft.CNqG295Fvu9B3w/5cY   ← Very strong but impossible to memorize
```

**Practical techniques for creating memorable high-entropy passwords**:

1. **Sentence to password**: Take the first letter of each word in a sentence:
    
    - `I really like the "51.502: Systems Security" course!`  
        → `Irlt"51.502:SS"c!`
2. **Passphrase** (random words):
    
    - `CorrectHorseBatteryStaple` — popularized by xkcd, high entropy
3. **Random words + tweaks**:
    
    - `--31_throw_SIGNAL_march_74--` — hard to guess, easier to remember than random chars

---

### 10. Password Policies

Organizational password policies typically include:

- **Format restrictions**: minimum length, mandatory uppercase/lowercase/numbers/special characters
- **Forbidden words**: block dictionary words, common passwords, formats like dates/phone numbers
- **Blacklist**: even "good" passwords if they've been leaked in previous breaches
- **Expiration**: forced periodic password changes (every X days), no reuse of old passwords

> [!warning] Controversy Around Password Expiration Recent research shows that forced expiration is actually harmful: users choose weaker and more predictable passwords (e.g., `Password1!` → `Password2!`). NIST SP 800-63B currently **does not recommend** forced periodic expiration, unless there is evidence of compromise.

---

### 11. One-Time Password (OTP)

OTP solves the problem of **password eavesdropping** — each login uses a different password.

#### 11.1 Lamport's OTP (Hash Chain)

**Setup**:

```
Alice computes: s → H(s) → H²(s) → H³(s) → ... → H¹⁰⁰⁰(s)
Alice sends H¹⁰⁰⁰(s) to the server (bootstrap)
```

**Authentication**:

- Session 1: Alice sends H⁹⁹⁹(s) → Server verifies: `H(H⁹⁹⁹(s)) == H¹⁰⁰⁰(s)` ✓
- Session 2: Alice sends H⁹⁹⁸(s) → Server verifies: `H(H⁹⁹⁸(s)) == H⁹⁹⁹(s)` ✓
- ...

**Property**: A used OTP cannot be reused because the attacker would need to reverse the hash function.

#### 11.2 Time-based OTP (TOTP)

```
Alice bootstraps the server with K (shared secret)
Each authentication: Alice sends H(K, T) — T is the current timestamp
```

- Server knows K and T → verifies independently
- **Used in**: Google Authenticator, 2FA apps

#### 11.3 Counter-based OTP (HOTP)

```
Alice and server share K and counter C (starting from 0)
Each session: Alice sends H(K, C++) — C increments after each use
```

#### 11.4 Challenge-Response OTP (Nonce-based)

```
Alice bootstraps the server with K
Each session: Server sends a random Nonce
Alice sends H(K, Nonce)
```

- Server verifies: recomputes H(K, Nonce) and compares
- **Advantage**: No time synchronization needed, no counter needed

---

### 12. Two-Factor Authentication (2FA)

**Problem with single-factor**: If the password is stolen (phishing, breach…), the attacker can log in.

**Solution**: Combine 2 factors:

- **Passwords** (something you know) + **OTP** (something you have)

**Practical implementations**:

- **Physical tokens**: devices that generate OTPs
- **Apps**: Google Authenticator, Authy (TOTP)
- **Universal 2nd Factor (U2F)**: USB or NFC tokens (YubiKey…)
- **Password + Device**: Confirmation via a registered phone

> [!note] Usability Trade-off 2FA significantly increases security but can be annoying if required for every login. Many systems apply risk-based authentication: only requiring 2FA when detecting a login from an unfamiliar device/location.

---

### 13. Alternative Authentication Methods

#### Evaluation Across Three Criteria

|Criterion|Description|
|---|---|
|**Usability**|Easy to learn, low error rate, easy to recover when lost|
|**Deployability**|Server cost, browser support, cost|
|**Security**|Resistant to observation, phishing, theft|

#### Certificates (Client Certificate Authentication)

- **Pros**: High security, no password to remember
- **Cons**: Difficult to manage for regular users, low deployability

#### Biometrics

- Fingerprint, face, iris, voice
- **Pros**: Unique, always "carried," convenient
- **Cons**:
    - Cannot be changed if compromised (you can't "change your fingerprint")
    - Privacy concerns
    - False acceptance/rejection rates
    - Can be spoofed (deepfakes, fake fingerprints)

---

### 14. OAuth 2.0 and OpenID Connect

> [!note] Additional Learning Resources
> 
> - **An Illustrated Guide to OAuth and OpenID Connect** (16:35): https://youtu.be/t18YB3xDfXI
> - **OAuth 2.0 and OpenID Connect (in plain English)** (~1hr): https://youtu.be/996OiexHze0

**OAuth 2.0** is an **Authorization** framework that allows third-party applications to access resources on behalf of the user without knowing their password.

**OpenID Connect (OIDC)** is an **Authentication** layer built on top of OAuth 2.0 — providing an ID Token that confirms the user's identity.

---

## Illustrative Example

### In-class Activity: Mini Rainbow Table

**Parameters**:

- Startpoints: 32, 14, 11, 20
- Chain length: 4 (H and R used 3 times each)
- R(x) = 5×x; H(x) = x mod 13

**Chain from startpoint 32**:

```
32 → H(32) = 32 mod 13 = 6 → R(6) = 30 → H(30) = 30 mod 13 = 4 → R(4) = 20 (endpoint)
```

**Cracking hash h = 9**:

1. R(9) = 45 → check endpoint? No
2. H(45) = 45 mod 13 = 6 → R(6) = 30 → check? No
3. H(30) = 4 → R(4) = 20 → **20 is an endpoint!** → find chain with endpoint 20 → reconstruct chain → find preimage

---

## Password Hashing Algorithm Comparison

|Algorithm|Memory-hard|ASIC-resistant|GPU-resistant|Standardized|
|---|---|---|---|---|
|MD5/SHA-256|❌|❌|❌|Not for passwords|
|PBKDF2|❌|❌|❌|NIST/FIPS-140|
|bcrypt|❌|Partial|Partial|Widely used|
|scrypt|✅|✅|Partial|—|
|**Argon2**|✅|✅|✅|**Recommended**|

---

## Summary & Takeaways

- **Authentication ≠ Authorization**: AuthN verifies identity, AuthZ grants permissions. OAuth is AuthZ, OpenID Connect is AuthN.
- **Overall security = the weakest link**: `security = min(password_security, recovery_security)` — weak recovery means the entire system is weak.
- **Never store passwords in cleartext**; do not use MD5/SHA-256 to hash passwords — use **Argon2** or bcrypt with a high work factor.
- **Salt** defeats rainbow tables by forcing attackers to attack each user individually.
- **HoneyWords** is a clever breach detection mechanism — triggering an alarm when a decoy password is used.
- **OTP** solves the password eavesdropping problem; **2FA** provides protection even when passwords are stolen.
- There is no perfect authentication solution — there is always a trade-off between **Usability**, **Deployability**, and **Security**.

---

## Knowledge Links

- [[Cryptographic Hash Functions]]
- [[Key Derivation Functions]]
- [[Multi-Factor Authentication]]
- [[OAuth 2.0]]
- [[OpenID Connect]]
- [[HoneyPot Systems]]
- [[Rainbow Tables]]
- [[Network Security]]
- [[SS-Week4]]
